# Task 9 Canonical FileAuthority Vertical Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `FileAuthorityCore` its first production caller by routing `F_SETPIPE_SZ` through a serialized transaction over the exact canonical `Arc<FileTable>` and `Arc<FileDescription>` captured from the kernel context, without creating or synchronizing a second file-object store.

**Architecture:** Production launch authenticates one run/client but does not issue `CreateTable`; the model tables already used by the authority test suite remain empty in production. A direct-only `CanonicalAuthorityTarget` accompanies the value-only command to the in-carrier core and contains the exact captured `Arc<FileTable>` plus a `FileSlotAuthority` generation token. The core resolves and mutates the canonical description under its existing transaction lock; no production table/description registry, lifecycle binding, observer, or mirrored snapshot is introduced in this Task 9 slice.

**Tech Stack:** Rust, `Arc`, Carrick `KernelContext`, `FileTable`, `FileDescription`, direct `FileAuthorityTransport`, typed K1 migration ledgers, signed HVPatch conformance.

**Spec:** `docs/superpowers/plans/2026-08-12-per-run-file-authority-atomic-migration.md`, as amended by the user's 2026-08-28 approval that the Task 9 production slice operate on the existing canonical kernel objects.

## Why this supersedes the first replacement draft

Independent review rejected the first draft before implementation because it tried to combine Task 9's first direct production call with the later full lifecycle/backend cutover. That created a root-binding bootstrap cycle, required a complete description registry while 75 creation paths remained direct, could not atomically publish prepared bindings, omitted fd-reuse freshness, collided independent ID allocators, overstated host-fork/IPC support, and lacked close-effect ordering. This plan removes those false claims and implements only the direct, in-carrier vertical slice Task 9 actually gates.

## Global Constraints

- The production authority core must not allocate, create, copy, or populate a private table or description for this path. Its existing model maps are test-only behavior and remain empty in a production `FileAuthorityRun`.
- Do not add a canonical/legacy enum, mode switch, read-through fallback, dual write, synchronization copy, observer registry, or lazy semantic snapshot.
- The exact captured `Arc<FileTable>` is a trusted direct-transport sidecar, never encoded in `Request` and never stored as a second ownership graph. Every outcome-determinant scalar, including host queued-byte accounting, remains value-only in the command so deduplication and a future IPC core see the complete operation.
- `FileSlotAuthority` is the fd-reuse freshness proof: table ID, fd number, slot generation, and description ID must all be validated before obtaining the canonical description. Never authorize by fd number alone.
- `ObjectGeneration` remains object-incarnation identity. Do not reinterpret it as a mutation revision.
- `AuthorityFatal` remains run-fatal and distinct from guest-semantic `AuthorityError`; neither can fall back to direct mutation.
- Only `F_SETPIPE_SZ` moves in this slice. Do not migrate close, close-range, fork/clone/exec bindings, `ThreadResources`, host-fork, IPC, or the other heterogeneous `slot_description_mutation` entries.
- Do not reintroduce `OpenDescription::base`, `base_mut`, a generic mutable backing accessor, or any bridge removed by FD seam Task 5.
- Preserve both in-memory and host-pipe behavior: shared cross-end capacity, page rounding/minimum, `EINVAL`, `EPERM`, `EBUSY`, `EBADF`, buffered-byte checks, and one canonical description revision publication after success only.
- Keep Carrick and Docker phases serialized. Guest execution uses a newly built and signed binary with a scoped `CARRICK_RUN_ID`.
- Full `just lint-domains` may stop only at the checked-in host-authority positional inventory drift when it reports `changed=[]`; never refresh that unrelated inventory.

---

### Task 1: Add a direct canonical target without creating production model objects

**Files:**
- Modify: `crates/carrick-runtime/src/file_authority/types.rs`
- Modify: `crates/carrick-runtime/src/file_authority/transport.rs`
- Modify: `crates/carrick-runtime/src/file_authority/core.rs`
- Modify: `crates/carrick-runtime/src/file_authority/root.rs`
- Modify: `crates/carrick-runtime/src/file_authority/tests.rs`

**Interfaces:**
- Consumes: `Arc<kernel::FileTable>`, `kernel::FileSlotAuthority`, existing `AuthorityCall`, and the direct transport serialization lock.
- Produces: `CanonicalAuthorityTarget`, `DirectFileAuthority::transact_canonical`, `FileAuthorityCore::execute_canonical_call`, and `FileAuthorityRun::launch(root_table: Arc<FileTable>)` with no production `CreateTable` request. `FileAuthorityRun` retains the concrete direct transport plus a `Weak<FileTable>` root identity; this slice does not put Arc-bearing targets on the IPC-shaped transport trait.

- [ ] **Step 1: Add red production-root and canonical-path isolation tests**

Add tests with these exact assertions:

```rust
#[test]
fn production_root_binding_names_the_kernel_table_without_creating_a_model_table() {
    let ids = ObjectIdRegistry::new();
    let table = Arc::new(FileTable::new(ids.file_table_id().expect("table id")));
    let run = FileAuthorityRun::launch(Arc::clone(&table)).expect("authority launch");

    assert_eq!(run.binding().table, table.id());
    assert_eq!(run.model_table_count_for_test(), 0);
    assert_eq!(run.model_description_count_for_test(), 0);
}
```

```rust
#[test]
fn canonical_path_rejects_a_model_command_without_fallback() {
    // Construct a valid direct target, then send an existing model-only
    // command through the canonical entry point.
    assert!(matches!(fatal, AuthorityFatal::InvariantViolation(_)));
    assert_eq!(run.model_table_count_for_test(), 0);
}
```

Also add cross-entry replay-ordering tests: an already completed model request replayed through `transact_canonical` is fatal; an already completed canonical request replayed through ordinary `transact` is fatal; and a duplicate canonical request with a mismatched target sidecar is fatal rather than replaying the cached response.

- [ ] **Step 2: Run both tests red**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib production_root_binding_names_the_kernel_table -- --test-threads=1 --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib canonical_path_rejects_a_model_command_without_fallback -- --test-threads=1 --nocapture
```

Expected: FAIL because launch creates a private model table and there is no canonical target call.

- [ ] **Step 3: Define the transport-local target**

Define in `types.rs` without `Clone`, `Eq`, serialization, or inclusion in `Request`:

```rust
pub(crate) struct CanonicalAuthorityTarget {
    pub(crate) table: Arc<crate::kernel::FileTable>,
    pub(crate) slot: crate::kernel::FileSlotAuthority,
}
```

Add a `Debug` implementation that prints typed IDs/generations only, never backing contents or host fds.

- [ ] **Step 4: Add the direct canonical transaction path**

Add:

```rust
impl DirectFileAuthority {
    pub(crate) fn transact_canonical(
        &self,
        call: AuthorityCall,
        target: CanonicalAuthorityTarget,
    ) -> Result<AuthorityReply, AuthorityFatal> {
        self.core.lock().execute_canonical_call(call, target)
    }
}
```

Both entry points perform entry-family validation before any dedup lookup: ordinary `execute_call` rejects a canonical command, while `execute_canonical_call` rejects a model command and structurally checks `target.slot == command.slot` plus `target.table.id() == command.slot.table()`. Only after those checks do they share epoch, client, request-order, capability, and dedup handling. This ordering prevents a terminal model response from replaying through the canonical entry, a terminal canonical response from replaying through the model entry, or a cached canonical response from bypassing a mismatched sidecar. Refactor the common authentication/dedup body into one private helper so the paths cannot otherwise drift.

For a dedup hit, replay the already committed canonical response without re-resolving live slot state; a legitimate retry remains replayable after close/reuse. Only a fresh canonical request calls the single-lock `resolve_slot_authority` and dispatches the mutation. Any entry-family mismatch is `AuthorityFatal::InvariantViolation`; it never selects a fallback path.

- [ ] **Step 5: Stop creating the production model root**

Change production launch to accept the exact already-allocated `Arc<FileTable>`. Register the run client, construct `FileAuthorityBinding { epoch, client, table: root_table.id(), generation: ObjectGeneration::INITIAL }`, retain `Weak<FileTable>` for exact-root authentication, and do not issue `Command::CreateTable` or the model `ListSlots` health check. Retain `Arc<DirectFileAuthority>` in `FileAuthorityRun` for this in-carrier slice rather than erasing it behind `Arc<dyn FileAuthorityTransport>`; the ordinary `execute` path still calls the trait implementation. Add `#[cfg(test)]` count accessors as inherent methods on `DirectFileAuthority`, exposed through `FileAuthorityRun` test helpers. Do not add Arc-bearing methods to `FileAuthorityTransport`, and do not expose the core or its maps to production callers.

Activation upgrades the retained weak root and uses `Arc::ptr_eq` to make repeated activation idempotent only for that same Arc; a different Arc at activation is fatal. Canonical calls deliberately do not compare against the launch root: exec, copied-files clone, and `CLOSE_RANGE_UNSHARE` legitimately publish successor `FileTable` Arcs while this slice omits lifecycle registration. Their table sidecar comes only from the dispatcher's internally captured `KernelContext`, never from guest-controlled data, and is authenticated by matching its typed ID to the complete command slot token before single-lock slot resolution.

- [ ] **Step 6: Run focused and authority-model gates**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib production_root_binding_names_the_kernel_table -- --test-threads=1 --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib canonical_path_rejects_a_model_command_without_fallback -- --test-threads=1 --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib file_authority:: -- --test-threads=1 --nocapture
```

- [ ] **Step 7: Commit**

```bash
git add crates/carrick-runtime/src/file_authority
git commit -m "feat(runtime): add canonical FileAuthority target"
```

---

### Task 2: Add one canonical pipe-capacity mutation without reopening generic backing access

**Files:**
- Modify: `crates/carrick-runtime/src/kernel/objects.rs`
- Modify: `crates/carrick-runtime/src/dispatch/fd_table.rs`
- Modify: `crates/carrick-runtime/src/file_authority/core.rs`
- Modify: `crates/carrick-runtime/src/file_authority/types.rs`
- Test: `crates/carrick-runtime/src/file_authority/tests.rs`
- Test: `crates/carrick-runtime/src/dispatch/fs/tests.rs`

**Interfaces:**
- Consumes: a validated `FileSlotAuthority`, the new single-lock `FileTable::resolve_slot_authority`, and the concrete `RwLock<OpenDescription>` backing already owned by the canonical `FileDescription`.
- Produces: `Command::SetCanonicalPipeCapacity { slot, capacity }` and one narrow `FileDescription::set_pipe_capacity_from_authority` method.

- [ ] **Step 1: Add red semantic and exact-object tests**

Test all outcomes against one canonical table/description graph:

- successful in-memory resize publishes one description revision and changes both pipe ends' shared capacity;
- host-pipe resize changes the exact installed description;
- shrink below queued bytes returns `EBUSY` without state/revision change;
- request above 1 MiB returns `EPERM`;
- value above `i32::MAX` returns `EINVAL`;
- a non-pipe or closed backing returns `EBADF`; and
- replacing the fd after token capture returns `StaleSlot` without touching the replacement.
- atomic resolution returns one exact description or `StaleSlot` even when a close/reuse writer is queued at the lock boundary; use a held table write guard/barrier in the test so this is an interleaving test, not only a sequential replacement.
- `F_SETPIPE_SZ` still succeeds through the canonical path after exec or `CLOSE_RANGE_UNSHARE` publishes a legitimate successor table Arc; activation is not repeated and the old root is not used as syscall authorization.

Include the moved sequential fd-reuse test here:

```rust
#[test]
fn canonical_target_rejects_a_closed_and_reused_fd_generation() {
    let fixture = CanonicalPipeFixture::new(3);
    let stale = fixture.table.capture_slot_authority(fixture.fd).expect("slot token");
    fixture.replace_fd_with_fresh_pipe();

    let outcome = fixture.call_set_capacity(stale, 131_072);

    assert!(matches!(outcome, Outcome::Rejected(AuthorityError::StaleSlot { .. })));
    assert_eq!(fixture.current_capacity(), fixture.initial_capacity());
}
```

- [ ] **Step 2: Run the focused tests red**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib canonical_pipe_capacity_ -- --test-threads=1 --nocapture
```

- [ ] **Step 3: Add the value-only command**

Add:

```rust
SetCanonicalPipeCapacity {
    slot: crate::kernel::FileSlotAuthority,
    capacity: PipeCapacity,
    accounting: crate::kernel::PipeCapacityAccounting,
},
```

Define `kernel::PipeCapacityAccounting` as a value-only enum with `InMemory` and `Host { queued_bytes: u64 }` variants, beside the canonical description operation rather than making the kernel depend on FileAuthority types. The command repeats the target token intentionally so request authentication and dedup compare the full value-only operation, including the outcome-determinant host observation. Command/target structural checks occur before dedup as specified in Task 1. The single-lock `resolve_slot_authority` freshness check occurs only for a fresh request after a dedup miss; failure returns `StaleSlot`.

Make `PipeCapacity::MAX` and its checked constructor available to production code. The dispatcher performs Linux errno-specific argument validation first, then constructs the typed nonzero, bounded value; invalid values must not be representable in the authority command.

Add a distinct committed result, for example:

```rust
CanonicalPipeCapacitySet {
    description: FileDescriptionId,
    capacity: PipeCapacity,
    description_revision: u64,
}
```

Do not reuse model-only `Outcome::PipeCapacitySet`, which requires a `PipeId` and stream revision. Advance `Response.authority_revision` exactly as for any accepted command; the returned `description_revision` is the distinct kernel `FileDescription` revision after the one successful publication. Change `FileDescription::publish_mutation()` to return that canonical `u64` (or read it while still under the same lifecycle transition); never wrap it in file-authority `Revision`.

- [ ] **Step 4: Add one narrow typed mutation seam**

Add an object-safe, narrow method to `kernel::FileDescriptionBacking`, with a default unsupported result, for example:

```rust
fn set_pipe_capacity_from_authority(
    &self,
    capacity: i64,
    accounting: PipeCapacityAccounting,
) -> Result<i64, PipeCapacityMutationError> {
    Err(PipeCapacityMutationError::NotPipe)
}
```

Define `kernel::PipeCapacityMutationError` beside the operation, with `NotPipe`, `Semantic(LinuxErrno)`, and `AccountingMismatch`; this keeps the canonical object layer independent of FileAuthority. Implement the backing method only for `RwLock<OpenDescription>` in `dispatch/fd_table.rs`, where the concrete dispatch backing is visible. Match only `PipeReader`, `PipeWriter`, and `HostPipe`; do not add `OpenDescription::base`, `base_mut`, or a generic mutable accessor. Add `FileDescription::set_pipe_capacity_from_authority(capacity, accounting)` in `kernel/objects.rs`, where the private lifecycle/mutation lock can legally be acquired; it invokes the backing method once under that lock and publishes exactly once after success. The FileAuthority core translates `NotPipe`/Closed to semantic `EBADF`, preserves semantic `EBUSY`, and treats only an accounting-kind mismatch on a live pipe backing as `AuthorityFatal::InvariantViolation`.

The command's `PipeCapacityAccounting` is `InMemory` for an in-memory pipe; for a host pipe it contains the queued-byte observation produced by the existing dispatcher accounting path, including the opposite read end and staged splice bytes. It is part of `Request` equality/dedup but is not a generic callback or backing accessor. The Arc table remains sidecar-only. Computing the host observation before the authority round trip has the same bounded race as the pre-cutover implementation (queue contents may change between its check and capacity-cell update); this task must not weaken that behavior, and a future stronger reservation protocol is outside this slice.

For in-memory pipe ends, use `PipeInner::set_capacity` so the buffer-length check and shared cross-end capacity remain atomic. For host pipes, perform the exact buffered-byte check and update the existing shared capacity cell. The `FileDescription` method acquires its private lifecycle/mutation lock before invoking the backing method, returns a typed error without publication on rejection, and calls `publish_mutation()` exactly once after success. No extension impl outside `kernel::objects` may access the private lifecycle lock.

- [ ] **Step 5: Resolve the canonical description safely**

Add `FileTable::resolve_slot_authority(FileSlotAuthority) -> Option<Arc<FileDescription>>`. It acquires `open_files.read()` exactly once, checks table ID, fd number, slot generation, and description ID against that one guard, and clones the exact description before releasing the guard. Do not compose `validate_slot_authority()` with `slot()`. Release the table lock before taking the description mutation lock. If close/reuse wins the table lock first, resolution returns `StaleSlot`; if resolution wins first, the retained Arc names the original description even if the fd number is later reused.

- [ ] **Step 6: Run focused and full authority tests**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib canonical_pipe_capacity_ -- --test-threads=1 --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib file_authority:: -- --test-threads=1 --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib --no-run
```

- [ ] **Step 7: Commit**

```bash
git add crates/carrick-runtime/src/file_authority crates/carrick-runtime/src/kernel/objects.rs crates/carrick-runtime/src/dispatch/fd_table.rs crates/carrick-runtime/src/dispatch/fs/tests.rs
git commit -m "feat(runtime): mutate canonical pipe capacity in FileAuthority"
```

---

### Task 3: Activate on the final bound root and route the production syscall

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs`
- Modify: `crates/carrick-runtime/src/threaded_loop.rs`
- Modify: `crates/carrick-runtime/src/runtime.rs`
- Modify: `crates/carrick-runtime/src/hvpatch/mod.rs`
- Modify: `crates/carrick-runtime/src/dispatch/fs.rs`
- Test: inline tests in `crates/carrick-runtime/src/dispatch/mod.rs`
- Test: `crates/carrick-runtime/src/dispatch/fs/tests.rs`

**Interfaces:**
- Consumes: final captured `KernelContext.resources().files()`, `FileAuthorityRun::launch(Arc<FileTable>)`, and `DirectFileAuthority::transact_canonical`.
- Produces: one `SyscallDispatcher::authority_call` that takes the exact canonical table/slot target and preserves fatal versus semantic errors.

- [ ] **Step 1: Add red activation/error tests**

Prove that activation after HVPatch binding names `process_context.resources().files().id()`, repeated activation of the same table is idempotent, activation against a different final table is fatal, semantic rejection maps to the exact Linux errno, and an injected `AuthorityFatal` never invokes the old direct mutation.

- [ ] **Step 2: Move activation to the final binding point**

Change activation to accept the final captured `Arc<FileTable>` explicitly. Remove the premature top-level activation that observes the constructor bootstrap table. In `hvpatch/mod.rs`, immediately after the root `dispatcher.bind_hvpatch_process(context.clone())` final binding (currently near line 1347), capture the bound one-task kernel context, pass its `resources().files()` Arc to the fallible activation, and propagate failure as `RuntimeError::Configuration`. In the one-task path, activate after its final kernel binding is established and pass that final Arc. Repeated activation is idempotent only when `Arc::ptr_eq` confirms the same retained root; any different Arc, including a foreign same-ID table, is fatal. Do not add a binding to `ThreadResources` in this task.

- [ ] **Step 3: Add the one production entry point**

Define:

```rust
pub(crate) enum AuthorityCallError {
    Rejected(AuthorityError),
    Fatal(AuthorityFatal),
}

pub(crate) fn authority_call(
    &self,
    table: Arc<crate::kernel::FileTable>,
    slot: crate::kernel::FileSlotAuthority,
    command: Command,
) -> Result<Outcome, AuthorityCallError>
```

Treat the supplied table Arc as trusted only because it was captured internally from the current `KernelContext`; authenticate `table.id()` against the command and target token, allocate exactly one request ID, call the retained concrete direct transport's `transact_canonical`, map only `Outcome::Rejected(error)` to `Rejected`, and preserve transport/protocol failure as `Fatal`. Do not compare syscall tables to the launch root: legitimate exec/unshare successor tables must work. There is no retry or direct fallback.

- [ ] **Step 4: Route `F_SETPIPE_SZ`**

Keep guest argument parsing and Linux page/max policy at the syscall boundary only where it cannot race. Capture the exact table and `FileSlotAuthority`; for a host pipe, compute the narrow queued-byte accounting observation through the existing `host_pipe_capacity_state` path before issuing `SetCanonicalPipeCapacity`. Then issue the canonical command and remove the old direct backing mutation. `F_GETPIPE_SZ` remains a read in this slice.

Map semantic errors to `EINVAL`, `EPERM`, `EBUSY`, or `EBADF`. Route `Fatal` through the new run-fatal dispatch error below; never map it to guest errno.

Add an explicit non-errno dispatch error variant such as `DispatchError::FileAuthorityFatal(AuthorityFatal)`. `lower_handler_result` must leave this variant run-fatal, just like the existing non-errno fatal path. Do not add a `DispatchOutcome` fatal case, and do not collapse a transport, authentication, dedup, or invariant failure into `LinuxErrno`.

- [ ] **Step 5: Run focused dispatcher gates**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib dispatcher_activates_one_authenticated_file_authority_root -- --test-threads=1 --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib canonical_pipe_capacity_ -- --test-threads=1 --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib fcntl_pipe -- --test-threads=1 --nocapture
```

- [ ] **Step 6: Commit**

```bash
git add crates/carrick-runtime/src/dispatch crates/carrick-runtime/src/threaded_loop.rs crates/carrick-runtime/src/runtime.rs crates/carrick-runtime/src/hvpatch/mod.rs
git commit -m "feat(runtime): route pipe capacity through FileAuthority"
```

---

### Task 4: Reconcile measured K1 evidence and run host/signed acceptance

**Files:**
- Modify: `scripts/migrate/k1-file-authority-operation-inventory.json`
- Modify: `scripts/migrate/k1-file-authority-callsite-taxonomy.json`
- Modify: `scripts/migrate/k1-burndown-ceiling.json` only if the measured family/category count decreases
- Modify: `.superpowers/sdd/2026-08-27-fd-description-seam/progress.md`

- [ ] **Step 1: Re-measure rather than applying stale counts**

Record that the live taxonomy began with 14 heterogeneous `slot_description_mutation` entries and that `F_SETPIPE_SZ` was classified under `inspect_misc`. Regenerate only the entries whose final source locations or authority shapes changed. Do not claim the 14-entry family is zero and do not set its ceiling to zero.

- [ ] **Step 2: Prove the production path is unique**

```bash
rg -n 'LINUX_F_SETPIPE_SZ' crates/carrick-runtime/src/dispatch/fs.rs
rg -n 'set_pipe_capacity\(' crates/carrick-runtime/src/dispatch crates/carrick-runtime/src/file_authority
rg -n 'fn (base|base_mut)\(' crates/carrick-runtime/src/dispatch/fd_table.rs
```

Expected: the syscall has one authority call and no direct production mutation; capacity mutation exists only in the narrow authority seam and underlying pipe primitive; the generic base-accessor search is empty.

- [ ] **Step 3: Run K1 and host gates**

```bash
python3 scripts/migrate/check-k1-file-authority-inventory.py
python3 scripts/migrate/check-k1-file-authority-taxonomy.py
python3 scripts/migrate/check-k1-burndown.py
just fmt
RUSTC_WRAPPER= just test
RUSTC_WRAPPER= just test-integration
RUSTC_WRAPPER= just clippy
RUSTC_WRAPPER= just doc
just fmt-check
git diff --check
RUSTC_WRAPPER= just lint-domains
```

Expected: all gates pass except the known host-authority positional inventory stop, which must report `changed=[]`.

- [ ] **Step 4: Run exact signed acceptance on one recorded artifact**

Build/sign once and record source HEAD, binary SHA-256, CDHash, LC_UUID, hypervisor entitlement, and `__dof_carrick`. Run:

```bash
RUSTC_WRAPPER= just build
CARRICK_RUN_ID=fd-task9-final CARRICK_PROBE_FILTER=fcntlpipesz,pipeszcrossend,spawnflagmatrix,epollcluster RUSTC_WRAPPER= just conformance-probes
```

Run the LTP `fcntl30` and `fcntl37` rows on the same binary. Run Carrick first and Docker second, never concurrently. Grep binary logs with `grep -a`; reap only `fd-task9-final` with `scripts/sudo/kill.sh fd-task9-final`.

- [ ] **Step 5: Commit**

```bash
git add scripts/migrate/k1-burndown-ceiling.json scripts/migrate/k1-file-authority-operation-inventory.json scripts/migrate/k1-file-authority-callsite-taxonomy.json
git commit -m "chore(runtime): record canonical pipe authority burndown"
```

## Completion audit

- [ ] Production launch creates no private authority table or description.
- [ ] The direct authority call receives the exact captured canonical table and a complete fd-generation token.
- [ ] Close/reuse cannot redirect a mutation to a replacement description.
- [ ] Successful capacity mutation publishes once; every rejection leaves state and revision unchanged.
- [ ] `F_SETPIPE_SZ` has no direct mutation fallback and fatal authority errors remain run-fatal.
- [ ] No generic backing accessor removed by Task 5 was reintroduced.
- [ ] Measured K1 ledgers and ceilings reflect only the actual final reduction.
- [ ] Full host gates and exact signed pipe probes pass on one recorded binary.
- [ ] This Task 9 slice makes no host-fork, IPC-equivalence, full lifecycle-binding, or close-family completion claim; those remain Wave 3/4 work under the approved migration plan and the later runtime-abstraction controller.
