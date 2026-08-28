# Task 9 Canonical FileAuthority Cutover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route the first production file-description mutation family through one `FileAuthority` that operates on the exact `Arc<FileTable>` and `Arc<FileDescription>` objects already published by the kernel, with no second slot or description store.

**Architecture:** `FileAuthorityCore` becomes the transaction coordinator and owner registry for the kernel's canonical file objects. Authority-created descriptions place their mutable state in one concrete `FileDescriptionBacking`; pre-existing dispatch descriptions are mutated through typed methods on the same canonical `FileDescription`. Fork, clone, exec, unshare, host-fork, and exit use prepared authority bindings: preparation may fail before kernel publication, publication is infallible, and dropping an unpublished preparation rolls it back.

**Tech Stack:** Rust, `Arc`, `parking_lot`, Carrick kernel object graph, direct `FileAuthorityTransport`, typed K1 migration ledgers, signed HVPatch conformance.

**Spec:** `docs/superpowers/plans/2026-08-12-per-run-file-authority-atomic-migration.md`, as amended by the user's 2026-08-28 approval that FileAuthority operate on the existing canonical kernel objects.

## Global Constraints

- There is one mutable slot map and one mutable description payload. Do not add a canonical/legacy enum, read-through fallback, dual write, synchronization copy, or production mode switch.
- The maps in `FileAuthorityCore` hold the exact canonical `Arc<FileTable>` and `Arc<FileDescription>` objects; lifecycle metadata may be separate but may not repeat slots, offsets, flags, readiness, pipe capacity, or backing state.
- `ObjectGeneration` authenticates an object incarnation. Mutation freshness uses canonical slot generation and canonical object revision; do not reinterpret `ObjectGeneration` as a mutation counter.
- Preserve `AuthorityFatal` separately from guest-semantic `AuthorityError`. Fatal authority failures terminate the run and never degrade to errno or a legacy path.
- Authority preparation may block before kernel publication. Kernel publication must not perform a fallible authority call or hold an authority lock. Dropping an unpublished preparation aborts it.
- Never transact while holding a kernel registry, table, description, stream, VFS, guest-memory, or host-wait lock.
- Preserve `FileCloseEvent`, epoll cleanup, mqueue rebinding, dnotify/inotify cleanup, classic-lock release, logical fd-reference hooks, and host-fd ownership ordering.
- Keep Carrick and Docker oracle phases serialized. Guest execution uses a newly built and signed binary with a scoped `CARRICK_RUN_ID`.
- The full `just lint-domains` gate is allowed to stop only at the checked-in host-authority positional inventory drift when it reports `changed=[]`; never refresh that unrelated inventory.

---

### Task 1: Replace the parallel FileAuthority object store with canonical kernel objects

**Files:**
- Modify: `crates/carrick-runtime/src/file_authority/core.rs`
- Modify: `crates/carrick-runtime/src/file_authority/backing.rs`
- Modify: `crates/carrick-runtime/src/file_authority/types.rs`
- Modify: `crates/carrick-runtime/src/file_authority/tests.rs`
- Modify: `crates/carrick-runtime/src/kernel/objects.rs`
- Modify: `crates/carrick-runtime/src/dispatch/fd_table.rs`

**Interfaces:**
- Consumes: `kernel::FileTable`, `kernel::FileDescription`, `kernel::FileSlot`, `DescriptionCommon`, `FileDescriptionBacking`, `FileTable::install`, `FileTable::slot`, and stable kernel IDs.
- Produces: `FileAuthorityCore::for_run(epoch, root: Arc<FileTable>)`, canonical `tables: BTreeMap<FileTableId, Arc<FileTable>>`, canonical `descriptions: BTreeMap<FileDescriptionId, Arc<FileDescription>>`, and `AuthorityDescriptionBacking` as the sole mutable payload for authority-created descriptions.

- [ ] **Step 1: Add red canonical-identity tests**

Add tests proving all four properties in `file_authority/tests.rs`:

```rust
#[test]
fn canonical_root_is_the_authority_root_without_a_second_slot_map() {
    let root = canonical_root_with_installed_synthetic_fd(7);
    let expected_table = root.id();
    let expected_description = root
        .slot(FileSlotNumber::for_open_fd(7).expect("fd"))
        .expect("canonical slot")
        .description();
    let mut harness = Harness::with_canonical_root(Arc::clone(&root));

    assert_eq!(harness.binding.table, expected_table);
    let resolved = harness.resolve_slot(7).expect("authority resolve");
    assert_eq!(resolved.description, expected_description.id());
    assert!(Arc::ptr_eq(
        &harness.canonical_description(resolved.description),
        &expected_description,
    ));
    assert_eq!(root.slot_count(), 1);
}
```

```rust
#[test]
fn authority_mutation_changes_the_same_canonical_description_arc() {
    let (root, pipe_description) = canonical_root_with_pipe(3);
    let before = pipe_description.revision_for_test();
    let mut harness = Harness::with_canonical_root(root);

    let outcome = harness.set_pipe_capacity(3, 131_072).expect("mutation");

    assert!(matches!(outcome, Outcome::PipeCapacitySet { .. }));
    assert_eq!(pipe_description.pipe_capacity_for_test(), Some(131_072));
    assert!(pipe_description.revision_for_test() > before);
}
```

The helper constructors must use the public kernel constructors and install into one real `FileTable`; they must not populate an authority-only table first.

- [ ] **Step 2: Run the tests red**

Run:

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib canonical_root_is_the_authority_root -- --test-threads=1 --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib authority_mutation_changes_the_same_canonical_description_arc -- --test-threads=1 --nocapture
```

Expected: FAIL because `FileAuthorityCore::for_run` has no canonical root and still allocates its own `FileTableState`/`FileDescriptionState` store.

- [ ] **Step 3: Make authority-created state a canonical backing**

Replace the authority-only `FileDescriptionState` payload with a concrete backing installed in the canonical `FileDescription`:

```rust
#[derive(Debug)]
pub(super) struct AuthorityDescriptionBacking {
    state: Mutex<AuthorityDescriptionState>,
}

#[derive(Debug)]
struct AuthorityDescriptionState {
    offset: FileOffset,
    access_mode: AccessMode,
    readiness: ReadinessSnapshot,
    backing: AuthorityBacking,
}
```

Implement `kernel::FileDescriptionBacking` for `AuthorityDescriptionBacking`. Snapshot and readiness read this one mutex. `DescriptionCommon` remains the single authority for status flags, async owner/signal, lease, seals, secretmem, and logical fd references.

- [ ] **Step 4: Convert the core maps without a compatibility representation**

Change the core fields to:

```rust
tables: BTreeMap<FileTableId, Arc<crate::kernel::FileTable>>,
descriptions: BTreeMap<FileDescriptionId, Arc<crate::kernel::FileDescription>>,
table_lifecycle: BTreeMap<FileTableId, CanonicalTableLifecycle>,
description_lifecycle: BTreeMap<FileDescriptionId, CanonicalDescriptionLifecycle>,
```

`CanonicalTableLifecycle` contains only generation, authority revision, and authenticated client bindings. `CanonicalDescriptionLifecycle` contains only generation, authority revision, and capability-lease count. Neither type may contain slots or mutable open-description semantics.

Delete `FileTableState`, `FileSlotState`, and the old semantic fields in `FileDescriptionState`; do not retain them behind an enum or `Option`.

- [ ] **Step 5: Convert every core command to the canonical map**

For table operations, resolve the exact `Arc<FileTable>` and use typed table methods. For description operations, resolve the exact `Arc<FileDescription>` and either:

- mutate `DescriptionCommon` for common state;
- downcast `AuthorityDescriptionBacking` for authority-created payloads; or
- call a typed canonical method implemented on `FileDescription` for an existing dispatch backing.

A backing/type mismatch returns `Outcome::Rejected(AuthorityError::WrongBacking { .. })`; a missing registered object returns the existing typed missing-object rejection. It must never fall back to a second map.

- [ ] **Step 6: Run the authority model and structural gates**

Run:

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib file_authority:: -- --test-threads=1 --nocapture
rg -n 'struct FileTableState|struct FileSlotState|struct FileDescriptionState' crates/carrick-runtime/src/file_authority
```

Expected: all authority tests PASS; the structural search returns no matches.

- [ ] **Step 7: Commit**

```bash
git add crates/carrick-runtime/src/file_authority crates/carrick-runtime/src/kernel/objects.rs crates/carrick-runtime/src/dispatch/fd_table.rs
git commit -m "refactor(runtime): canonicalize FileAuthority objects"
```

---

### Task 2: Bind production activation and preserve the fatal/semantic error boundary

**Files:**
- Modify: `crates/carrick-runtime/src/file_authority/root.rs`
- Modify: `crates/carrick-runtime/src/file_authority/types.rs`
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs`
- Modify: `crates/carrick-runtime/src/threaded_loop.rs`
- Modify: `crates/carrick-runtime/src/runtime.rs`
- Test: `crates/carrick-runtime/src/file_authority/tests.rs`
- Test: inline tests in `crates/carrick-runtime/src/dispatch/mod.rs`

**Interfaces:**
- Consumes: canonical `FileAuthorityCore::for_run(epoch, root)` from Task 1 and an exact captured `KernelContext.resources().files()`.
- Produces: `FileAuthorityRun::launch(root: Arc<FileTable>)`, `AuthorityCallError::{Rejected(AuthorityError), Fatal(AuthorityFatal)}`, and the sole `SyscallDispatcher::authority_call` production entry point.

- [ ] **Step 1: Add red activation and error-boundary tests**

Add tests proving:

```rust
assert_eq!(binding.table, captured_context.resources().files().id());
assert_eq!(binding.generation, ObjectGeneration::INITIAL);
```

Add one semantic rejection test expecting `AuthorityCallError::Rejected(_)`, and one injected transport failure expecting `AuthorityCallError::Fatal(AuthorityFatal::TransportUnavailable)`. Assert the fatal case does not invoke a legacy mutation closure.

- [ ] **Step 2: Run the tests red**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib dispatcher_activates_one_authenticated_file_authority_root -- --test-threads=1 --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib authority_call_preserves_fatal_and_semantic_errors -- --test-threads=1 --nocapture
```

Expected: FAIL because activation still launches an empty private root and the call API does not exist.

- [ ] **Step 3: Pass the exact root into launch**

Change activation to capture the final kernel context first and call:

```rust
FileAuthorityRun::launch(context.resources().files())
```

HVPatch activation must occur after `bind_hvpatch_process`; the discarded one-task constructor bootstrap table must never become the authority root. One-task/native activation uses its final bound context. Repeated activation is idempotent only when `Arc::ptr_eq` and the table ID both match; otherwise return `AuthorityFatal::InvariantViolation`.

- [ ] **Step 4: Add the one production call API**

Define:

```rust
pub(crate) enum AuthorityCallError {
    Rejected(AuthorityError),
    Fatal(AuthorityFatal),
}

pub(crate) fn authority_call(
    &self,
    binding: FileAuthorityBinding,
    command: Command,
    expected: ObjectGeneration,
) -> Result<Outcome, AuthorityCallError>
```

The method authenticates the passed binding against the run, calls the transport once, maps only `Outcome::Rejected(error)` to `Rejected`, maps transport/protocol failure to `Fatal`, and returns every committed outcome unchanged. There is no retry or fallback.

- [ ] **Step 5: Run focused and full host gates**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib file_authority::root::tests -- --test-threads=1 --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib dispatcher_activates_one_authenticated_file_authority_root -- --test-threads=1 --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib --no-run
```

- [ ] **Step 6: Commit**

```bash
git add crates/carrick-runtime/src/file_authority crates/carrick-runtime/src/dispatch/mod.rs crates/carrick-runtime/src/threaded_loop.rs crates/carrick-runtime/src/runtime.rs
git commit -m "feat(runtime): bind FileAuthority to the canonical root"
```

---

### Task 3: Prepare and publish canonical authority bindings with kernel lifecycle transactions

**Files:**
- Modify: `crates/carrick-runtime/src/file_authority/root.rs`
- Modify: `crates/carrick-runtime/src/file_authority/core.rs`
- Modify: `crates/carrick-runtime/src/file_authority/types.rs`
- Modify: `crates/carrick-runtime/src/kernel/objects.rs`
- Modify: `crates/carrick-runtime/src/kernel/operations.rs`
- Modify: `crates/carrick-runtime/src/kernel/exec.rs`
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs`
- Test: `crates/carrick-runtime/src/kernel/tests.rs`
- Test: existing inline tests in `kernel/operations.rs` and `kernel/exec.rs`

**Interfaces:**
- Consumes: the one `Arc<FileAuthorityRun>` and canonical object maps.
- Produces: `ThreadResources.file_authority: FileAuthorityBinding`, `PreparedFileTableBinding`, and prepare/commit/abort/retire lifecycle methods.

- [ ] **Step 1: Add red rollback and publication tests**

For fork-copy, thread clone with copied files, exec, host-fork copy, and `close_range(CLOSE_RANGE_UNSHARE)`, assert that the prepared successor binding names the exact successor `FileTable::id()`. For every existing failpoint before publication, assert the successor table is absent from the authority after the preparation drops. After publication, assert the binding is active before a child/thread can dispatch.

- [ ] **Step 2: Run the focused tests red**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib fork_publishes_task_and_independently_selected_resources -- --test-threads=1 --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib thread_clone_keeps_task_shared_but_can_copy_files_and_fs -- --test-threads=1 --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib every_exec_failpoint_preserves_published_generation -- --test-threads=1 --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib hvpatch_close_range_unshare_splits_clone_files_before_closing_child_fd -- --test-threads=1 --nocapture
```

- [ ] **Step 3: Put the binding in `ThreadResources`**

Add one value field:

```rust
file_authority: FileAuthorityBinding,
```

`ThreadResources::new`, `for_clone`, `for_exec`, and `with_files` must receive or derive the binding explicitly. Share copies the exact binding. Copy/exec consumes a committed prepared successor binding. The binding carries no mutable file state.

- [ ] **Step 4: Implement the prepared lifecycle token**

Define a non-`Clone` token:

```rust
pub(crate) struct PreparedFileTableBinding {
    run: Arc<FileAuthorityRun>,
    binding: FileAuthorityBinding,
    committed: bool,
}
```

`prepare_copy`, `prepare_exec`, and `prepare_external_copy` register the exact successor `Arc<FileTable>` in a prepared state and return this token. `commit(mut self)` makes the entry active and returns its binding without allocation or transport. `Drop` aborts an uncommitted entry. `prepare_share` authenticates and returns the already-active binding without creating a table.

- [ ] **Step 5: Attach tokens to existing kernel preparations**

Add the prepared token to `PreparedFork`, prepared thread clone state, and `PreparedExec`. Prepare it after the canonical successor table is constructed and before registry publication. Commit it immediately before the existing infallible kernel publication section; do not call transport while holding the registry lock. Because publication cannot fail after that point, authority and kernel become visible together.

Apply the same prepare/commit sequence to host-fork replacement and close-range unshare. `retain_stdio_only` must abort the superseded prepared binding and prepare the replacement table.

- [ ] **Step 6: Retire only after kernel publication**

Thread/task exit and exec retirement first publish kernel liveness changes, then call `FileAuthorityRun::retire_table_if_unreferenced` with the exact old `Arc<FileTable>`. Preserve the existing `Kernel::retire_file_table_generation` and dispatch `close_draining_file_table` effects. Authority-held `Arc`s are registry ownership, not evidence of a live task alias.

- [ ] **Step 7: Run lifecycle and full host tests**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib every_thread_exit_failpoint_preserves_the_live_thread -- --test-threads=1 --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib every_identity_and_exit_failpoint_restores_registry_state -- --test-threads=1 --nocapture
RUSTC_WRAPPER= just test
RUSTC_WRAPPER= just test-integration
```

- [ ] **Step 8: Commit**

```bash
git add crates/carrick-runtime/src/file_authority crates/carrick-runtime/src/kernel crates/carrick-runtime/src/dispatch/mod.rs
git commit -m "feat(runtime): transact FileAuthority lifecycle bindings"
```

---

### Task 4: Route the measured production mutation family and close the Task 9 gates

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/fd_helpers.rs`
- Modify: `crates/carrick-runtime/src/dispatch/fs.rs`
- Modify: `crates/carrick-runtime/src/dispatch/mqueue.rs`
- Modify: `crates/carrick-runtime/src/kernel/objects.rs`
- Modify: `crates/carrick-runtime/src/file_authority/core.rs`
- Modify: `crates/carrick-runtime/src/file_authority/tests.rs`
- Modify: `crates/carrick-runtime/src/dispatch/fs/tests.rs`
- Modify: `scripts/migrate/k1-file-authority-operation-inventory.json`
- Modify: `scripts/migrate/k1-file-authority-callsite-taxonomy.json`
- Modify: `scripts/migrate/k1-burndown-ceiling.json`

**Interfaces:**
- Consumes: canonical binding from captured `ThreadResources`, `SyscallDispatcher::authority_call`, canonical slot generation, and typed backing/downcast APIs.
- Produces: no direct production guard in `slot_description_mutation`, and `SetPipeCapacity` operating on the exact installed description.

- [ ] **Step 1: Re-measure the family before editing**

Run the taxonomy query and record all 14 entries. Classify the ten production entries separately from four test/API entries. Do not use the stale count of nine and do not claim `F_SETPIPE_SZ` belongs to this family until the checker classifies its actual site.

- [ ] **Step 2: Add red canonical pipe-capacity tests**

Add tests proving set/get across opposite pipe ends, shrink-below-buffered `EBUSY`, oversize `EPERM`, invalid signed size `EINVAL`, non-pipe `EBADF`, one canonical revision publication, and no mutation on semantic rejection. Re-run the tests against the pre-route binary/source and preserve the red receipt.

- [ ] **Step 3: Route `SetPipeCapacity` through the authority**

Resolve the slot from the captured canonical table, validate its slot generation and description ID, perform policy checks before mutation, and mutate the actual in-memory or host-pipe backing once. Return `Outcome::PipeCapacitySet` with the new authority and canonical description revisions. Convert `AuthorityCallError::Rejected` to the matching Linux errno at the syscall boundary; propagate `Fatal` to the run-fatal path.

- [ ] **Step 4: Route every measured production family site**

Replace the ten production `slot_description_mutation` guards in `fd_helpers.rs`, `fs.rs`, and `mqueue.rs` with closed authority commands. Delete each direct guard path in the same edit. Reclassify test helpers explicitly; delete the guard-returning production API in `kernel/objects.rs` once no production caller remains.

- [ ] **Step 5: Regenerate only the K1 ledgers affected by the final source**

Use each checker's documented refresh command, inspect stable-key additions/removals, and lower `slot_description_mutation` to zero only if the final taxonomy has no production entries. Do not refresh the host-authority transition inventory.

```bash
python3 scripts/migrate/check-k1-file-authority-inventory.py
python3 scripts/migrate/check-k1-file-authority-taxonomy.py
python3 scripts/migrate/check-k1-burndown.py
```

- [ ] **Step 6: Run host gates**

```bash
just fmt
RUSTC_WRAPPER= just test
RUSTC_WRAPPER= just test-integration
RUSTC_WRAPPER= just clippy
RUSTC_WRAPPER= just doc
just fmt-check
git diff --check
RUSTC_WRAPPER= just lint-domains
```

Expected: every gate passes except the known full-lint host-authority positional inventory stop, which must report `changed=[]`.

- [ ] **Step 7: Run signed acceptance on one exact artifact**

Build and sign once, record source HEAD plus binary SHA-256, CDHash, LC_UUID, entitlement, and `__dof_carrick`, then run exact Task 9-sensitive probes:

```bash
RUSTC_WRAPPER= just build
CARRICK_RUN_ID=fd-task9-final CARRICK_PROBE_FILTER=fcntlpipesz,pipeszcrossend,spawnflagmatrix,epollcluster RUSTC_WRAPPER= just conformance-probes
```

Run the LTP `fcntl30` and `fcntl37` rows through the canonical harness on the same binary. Run Carrick first and Docker second; never concurrently. Grep binary logs with `grep -a`. Reap only `fd-task9-final` with `scripts/sudo/kill.sh fd-task9-final`.

- [ ] **Step 8: Commit**

```bash
git add crates/carrick-runtime/src scripts/migrate/k1-burndown-ceiling.json scripts/migrate/k1-file-authority-operation-inventory.json scripts/migrate/k1-file-authority-callsite-taxonomy.json
git commit -m "feat(runtime): route canonical description mutations through FileAuthority"
```

## Completion audit

- [ ] `FileAuthorityCore` has no private slot or open-description semantic store.
- [ ] Production activation binds the exact final root table.
- [ ] Every published task/thread resource bundle carries the matching active authority binding.
- [ ] Every aborted fork/clone/exec/unshare preparation removes its unpublished authority entry.
- [ ] Fatal authority errors have no guest-errno or legacy fallback path.
- [ ] The live `slot_description_mutation` production family is empty and its ceiling was lowered from measured evidence.
- [ ] Full host tests and exact signed probes pass on one recorded binary.

