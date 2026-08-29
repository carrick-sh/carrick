# MM Authority and Structural Lock Order Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make current and foreign Linux address spaces distinct compile-time authorities, implement revision-safe HVPatch foreign reads and COW writes for all three cross-process consumers, and replace the inert debug lock hierarchy with a mintable `PtPause -> HostAlias` order.

**Architecture:** The kernel graph mints opaque `MmToken` values and token-bound read/write ranges. Current engines explicitly implement `CurrentMmMemory`; a carrier-owned `ForeignMmTransport` operates on coherent target snapshots through a private runtime facade. Per-MM mutation begins with a non-cloneable page-table exclusion guard that alone can mint the permit required by host-alias mutation; successful foreign writes consume a same-token `CowBroken` witness.

**Tech Stack:** Rust 2024, `parking_lot`, Hypervisor.framework/HVPatch, `carrick-guest-mem`, `carrick-hal`, Python 3 source gates, Cargo/Just, signed embed probes, Google Antigravity worker harness.

**Spec:** `docs/superpowers/specs/2026-08-28-mm-authority-lock-order-design.md`

## Global Constraints

- Read `/Volumes/CaseSensitive/carrick/AGENTS.md` before every delegated task.
- Work from `/Volumes/CaseSensitive/carrick/.worktrees/fd-description-seam`; every Antigravity write worker receives a dedicated worktree based on the exact canonical commit named in its brief.
- `MmId`, PID, TID, ASID, TTBR, VA, backend revision, VMA revision, and frame-inventory revision are distinct domains. Do not compare or substitute their raw integers.
- `MmToken`, token-bound ranges, `CowBroken`, `MmMutationGuard`, and `HostAliasPermit` have private fields and no general raw constructors.
- `GuestMemory` never implies foreign authority. `CurrentMmMemory` has explicit implementations and no blanket impl.
- The foreign transport is private behind the runtime facade; syscall dispatchers cannot call it with raw tuples.
- A foreign write consumes a `CowBroken` witness for the exact MM, range, revisions, and owner generation.
- Page-table exclusion precedes host-alias mutation. No operation waits for page-table exclusion while holding the host-alias phase.
- Preserve the current-MM hot path: no new allocation, vtable call, global lookup, or lock for ordinary syscall guest-pointer access.
- Preserve Linux partial-transfer and syscall-specific errno semantics.
- Every behavior change is red-first. Record the exact expected failure against the pre-fix code/artifact before implementation.
- Do not run Carrick and Docker concurrently. Oracle and Carrick phases are serialized.
- Guest execution on macOS uses `just build`, `just run`, or `just test-embed`; unsigned `cargo build` artifacts are compile-only.
- Use `RUSTC_WRAPPER=` for Cargo/Just gates.
- Only independently reviewed GREEN milestones fast-forward to local `main`; no push unless the user asks.
- Antigravity results are reviewed as diffs. Confirmed defects are sent back to the same conversation, with a maximum of three repair turns.

---

### Task 1: Fail-Closed MM Authority and Lock-Order Source Gate (RED)

**Files:**
- Create: `scripts/migrate/check-mm-authority.py`
- Modify: `justfile` `lint-domains` recipe

**Interfaces:**
- Consumes: production Rust leaves in `crates/carrick-runtime`, `crates/carrick-hal`, `crates/carrick-guest-mem`, and `crates/carrick-vmm-hvf`.
- Produces: `python3 scripts/migrate/check-mm-authority.py --self-test`, `--check`, and `--path <repo-relative-file>`.

- [ ] **Step 1: Write a tokenizer-backed checker with literal categories**

Reuse the comment/string/test-scope strategy in
`check-task-participant-witnesses.py`. The checker must emit these exact
categories:

```python
FORBIDDEN = {
    "foreign-current-memory": "current GuestMemory access in a foreign target arm",
    "raw-mm-authority": "raw pid/mm/ttbr/va tuple crosses an MM access API",
    "untyped-current-bound": "production dispatch generic uses GuestMemory without CurrentMmMemory",
    "unpermitted-host-alias": "host-alias acquisition lacks HostAliasPermit",
    "legacy-lock-order": "debug-only LockLevel authority remains",
    "public-mm-token-construction": "opaque MM authority is externally constructible",
    "blanket-current-impl": "CurrentMmMemory has a blanket implementation",
}
```

Fixtures must reject `process_vm_copy_self` or `memory.read_bytes` in an
`OtherGuest` arm, `LockOrderGuard::acquire`, `LockLevel`, and a
`HostAliasTransactions::begin_dispatch()` call without a permit argument, plus
`impl<T: GuestMemory> CurrentMmMemory for T` and its unconstrained equivalent.
Fixtures must accept comments, strings, `#[cfg(test)]`, `CurrentMmMemory`,
`MmRelation::Current`, runtime-facade `read_foreign`, and
`begin_dispatch(&permit)`.

- [ ] **Step 2: Prove fixture behavior**

```bash
python3 scripts/migrate/check-mm-authority.py --self-test
```

Expected: exit 0 with at least six negative and six positive fixtures, each
asserting category, file, and line.

- [ ] **Step 3: Wire the RED checker before host-authority compilation**

Add this exact line after the participant checker:

```just
    python3 scripts/migrate/check-mm-authority.py --check
```

- [ ] **Step 4: Prove the current tree is RED for real authority debt**

```bash
python3 scripts/migrate/check-mm-authority.py --check
```

Expected: non-zero findings for `kernel/foreign_mm.rs`, the foreign arm in
`dispatch/proc.rs`, `dispatch/lock_order.rs`, and unpermitted host-alias entry
points. Test-only memory fixtures must not appear.

- [ ] **Step 5: Commit the RED gate**

```bash
git add scripts/migrate/check-mm-authority.py justfile
git commit -m "test(runtime): reject untyped MM and lock-order authority"
```

Do not fast-forward this RED commit to `main`.

---

### Task 2: Kernel MM Authority Contracts (RED)

**Files:**
- Create: `crates/carrick-runtime/src/kernel/mm_access.rs`
- Modify: `crates/carrick-runtime/src/kernel/mod.rs`
- Modify: `crates/carrick-runtime/src/kernel/operations.rs` tests
- Modify: `crates/carrick-runtime/src/kernel/foreign_mm.rs` tests

**Interfaces:**
- Consumes: `KernelContext`, exact `TaskKey`, `Arc<Mm>`, and coherent `MmBackendSnapshot`.
- Produces: failing contracts for `MmToken`, `MmRelation`, `MmReadRange`, `MmWriteRange`, retained-MM behavior, and stale revision rejection.

- [ ] **Step 1: Add compile-pressure tests for current/foreign relation**

Add tests using the existing root/clone fixtures with these assertions:

```rust
let current = context.current_mm().expect("current MM authority");
assert_eq!(current.mm_id(), context.shared().mm().id());

let foreign = context
    .kernel()
    .foreign_mm(&context, child.task().key())
    .expect("foreign MM authority");
assert!(matches!(foreign, MmRelation::Foreign(_)));
```

Add a `CLONE_VM` child case asserting `MmRelation::Current(_)`, even though the
target task differs.

- [ ] **Step 2: Add exact-incarnation and retained-MM tests**

Retain a foreign token, exec or retire the target task, and assert:

```rust
assert_eq!(token.mm_id(), old_mm);
assert_ne!(replacement.shared().mm().id(), token.mm_id());
assert!(Arc::ptr_eq(token.mm(), &old_mm_arc));
```

Add a stale `TaskKey`/PID-reuse fixture and require
`MmAccessError::UnknownTask(stale_key)` rather than following the numeric PID.

- [ ] **Step 3: Add token-bound range tests**

Construct a snapshot with readable, read-only, writable, secret, and unmapped
VMAs. Assert:

```rust
assert!(token.read_range(GuestVa(0x1000), 16).is_ok());
assert!(matches!(
    token.write_range(GuestVa(0x2000), 16),
    Err(MmAccessError::WriteDenied { .. })
));
assert!(matches!(
    token.kernel_read_range(GuestVa(0x3000), 16),
    Err(MmAccessError::KernelHidden { .. })
));
```

Cover overflow, holes, cross-VMA ranges, and zero length.

- [ ] **Step 4: Prove the contracts fail only on missing APIs**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime kernel::mm_access --no-run
```

Expected: compile failure naming the missing authority types/methods, not a
fixture or import error.

- [ ] **Step 5: Commit the RED contracts**

```bash
git add crates/carrick-runtime/src/kernel/mm_access.rs \
  crates/carrick-runtime/src/kernel/mod.rs \
  crates/carrick-runtime/src/kernel/operations.rs \
  crates/carrick-runtime/src/kernel/foreign_mm.rs
git commit -m "test(runtime): specify kernel MM authority contracts"
```

---

### Task 3: Revision Domains, VMA Access, and Kernel Tokens

**Files:**
- Modify: `crates/carrick-hal/src/kernel.rs`
- Modify: `crates/carrick-hal/src/lib.rs`
- Modify: `crates/carrick-runtime/src/kernel/address.rs`
- Implement: `crates/carrick-runtime/src/kernel/mm_access.rs`
- Modify: `crates/carrick-runtime/src/kernel/objects.rs`
- Modify: `crates/carrick-runtime/src/kernel/core.rs`
- Modify: `crates/carrick-runtime/src/kernel/mod.rs`
- Modify: `crates/carrick-runtime/src/dispatch/mem.rs`
- Modify: every explicit `VmaSummary` fixture found by `rg -n 'VmaSummary \{' crates/carrick-runtime/src`

**Interfaces:**
- Consumes: Task registry and `MmBackend::snapshot`.
- Produces: `ForeignBackendRevision`, `ForeignVmaRevision`, `ForeignFrameInventoryRevision`, `VmaAccess`, opaque MM tokens/ranges, and `MmRelation`.

- [ ] **Step 1: Add non-interchangeable HAL revision newtypes**

Use one private-field newtype per domain:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForeignBackendRevision(u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForeignVmaRevision(u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForeignFrameInventoryRevision(u64);
```

Expose named `from_authority_raw` constructors and `raw_for_probe` projections;
do not implement cross-type `PartialEq`, `Add`, or `Sub`.

- [ ] **Step 2: Make VMA permissions part of every coherent snapshot**

Extend `VmaSummary` exactly:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmaAccess {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub kernel_visible: bool,
}

pub struct VmaSummary {
    pub start: GuestVa,
    pub end: GuestVa,
    pub access: VmaAccess,
}
```

Project access from `ProcMapEntry`/`MemoryProtections` in
`project_vma_summaries`; secret-memory coverage sets `kernel_visible = false`.
Every fixture must specify permissions explicitly.

- [ ] **Step 3: Implement opaque kernel authority**

Implement the spec's private-field types. Range validation walks sorted VMAs,
requires the requested access on every byte, and retains `&MmToken`:

```rust
impl MmToken {
    pub fn read_range(&self, start: GuestVa, len: usize)
        -> Result<Option<MmReadRange<'_>>, MmAccessError>;
    pub fn write_range(&self, start: GuestVa, len: usize)
        -> Result<Option<MmWriteRange<'_>>, MmAccessError>;
}
```

`None` is the only zero-length representation.

- [ ] **Step 4: Mint tokens only from exact kernel graph bindings**

`KernelContext::current_mm` authenticates `task_state_authority()` against the
context MM. `Kernel::foreign_mm` looks up exact `TaskKey`, snapshots the retained
`Arc<Mm>`, and compares MM identity/pointer to select `Current` versus `Foreign`.
Map snapshot timeout/churn to typed `MmAccessError` variants without flattening
them to `LinuxErrno` inside the kernel module.

- [ ] **Step 5: Pass kernel contracts and focused snapshot tests**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime kernel::mm_access
RUSTC_WRAPPER= cargo test -p carrick-runtime kernel::snapshot
RUSTC_WRAPPER= cargo test -p carrick-runtime dispatch::mem::tests --lib
```

Expected: all pass.

- [ ] **Step 6: Commit the kernel authority milestone**

```bash
git add crates/carrick-hal/src/kernel.rs crates/carrick-hal/src/lib.rs \
  crates/carrick-runtime/src/kernel crates/carrick-runtime/src/dispatch/mem.rs
git commit -m "feat(runtime): mint revision-bound MM authority"
```

Request independent review before integration.

---

### Task 4: Antigravity Current-MM Trait Census

**Files:**
- Modify: `crates/carrick-guest-mem/src/lib.rs`
- Modify: the 33 explicit `GuestMemory` implementation sites returned by `rg -n 'GuestMemory for' crates --glob '*.rs'`
- Modify: runtime/HAL generic bounds identified by `rg -n 'M: GuestMemory|impl GuestMemory|dyn GuestMemory' crates --glob '*.rs'`

**Interfaces:**
- Consumes: `GuestMemory` and the approved explicit marker name.
- Produces: `CurrentMmMemory: GuestMemory` with no blanket impl, explicit production/test implementations, and current-pointer dispatch bounds.

- [ ] **Step 1: Prove the behavioral source gate rejects blanket authority**

Run the Task 1 checker self-test and confirm its controlled negative fixtures
reject both blanket shapes while explicit implementations pass:

```bash
python3 scripts/migrate/check-mm-authority.py --self-test
```

Expected: the `blanket-current-impl` negative fixtures are reported internally
and the self-test exits 0. Do not add a Rust test that greps its own source.

- [ ] **Step 2: Launch one isolated Antigravity worker**

Create `agy/mm-current-census` from the canonical Task 3 commit. Brief the
worker to make only the mechanical trait declaration, explicit impls, imports,
and generic-bound changes. It must not edit MM tokens, foreign transport,
HVPatch COW, lock ordering, docs, or baselines.

Required worker gates:

```bash
RUSTC_WRAPPER= cargo check --workspace
RUSTC_WRAPPER= cargo test -p carrick-guest-mem
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib dispatch::
```

- [ ] **Step 3: Review every changed bound and implementation**

Codex checks that production engine implementations are explicit, wrappers such
as `SplitView` require `M: CurrentMmMemory`, and low-level helpers that are
genuinely address-space-neutral remain `GuestMemory`. Send any over-broad or
missing migration back to the same conversation.

- [ ] **Step 4: Integrate the approved worker patch and run the census**

```bash
rg -n 'GuestMemory for' crates --glob '*.rs'
python3 scripts/migrate/check-mm-authority.py --path crates/carrick-runtime/src
RUSTC_WRAPPER= cargo check --workspace
RUSTC_WRAPPER= cargo test -p carrick-guest-mem
```

Expected: every current-MM implementation is explicit; the checker has no
`untyped-current-bound` finding.

- [ ] **Step 5: Commit the canonical migration**

```bash
git add crates
git commit -m "refactor(memory): make current MM access explicit"
```

Record worker conversation, turns, commit/patch identity, corrections, and
review in the milestone ledger.

---

### Task 5: Carrier-Owned Foreign Read Transport

**Files:**
- Create: `crates/carrick-hal/src/foreign_mm.rs`
- Modify: `crates/carrick-hal/src/lib.rs`
- Modify: `crates/carrick-vmm-hvf/src/trap.rs`
- Modify: `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs`
- Modify: `crates/carrick-aarch64/src/engine.rs`
- Modify: `crates/carrick-runtime/src/hvpatch/mod.rs`
- Modify: `crates/carrick-runtime/src/kernel/mm_access.rs`
- Replace: `crates/carrick-runtime/src/kernel/foreign_mm.rs`

**Interfaces:**
- Consumes: validated `ForeignMmSnapshot` projected from `MmToken`.
- Produces: private runtime `MmAccessAuthority`, carrier-shared `MmAccessState`, and revision/owner-authenticated foreign reads.

- [ ] **Step 1: Add HAL transport DTOs and a mock contract**

Define `ForeignMmSnapshot`, `ForeignMmReadReceipt`,
`ForeignMmTransportError`, and object-safe `ForeignMmTransport::read`. Add a
mock transport test proving the snapshot carries distinct MM/binding/backend/
VMA/inventory domains and returns them unchanged in the receipt.

- [ ] **Step 2: Add RED backend tests for target-root translation**

In `trap.rs` tests build two MM roots mapping the same numeric VA to different
global frames. Require:

```rust
let bytes = authority.read(&target_snapshot, GuestVa(TEST_VA), 4).unwrap();
assert_eq!(bytes, TARGET_BYTES);
assert_ne!(bytes, CALLER_BYTES);
```

Add stale backend revision, stale VMA revision, stale inventory revision,
missing descriptor owner, and owner-generation-reuse cases. Expected result is
typed `Retry` or `OwnerStale`, never caller bytes.

- [ ] **Step 3: Factor per-MM shared read state from movable task state**

Introduce `Arc<MmAccessState>` containing stage-1 observer/backing,
protections, COW-armed metadata, inventory linkage, and mutation coordinator.
`HvfTaskState` retains an `Arc`; sibling threads/`CLONE_VM` clone it and forked
MM creation allocates a distinct state. Executor-local registers/mailbox stay
outside it.

- [ ] **Step 4: Implement owner-pinned foreign walks and reads**

Walk every stage-1 descriptor by copying table bytes through the exact live
global-frame owner. Authenticate the leaf's owner generation while holding the
owner lock and copy only within that pinned extent. Validate all three snapshot
revisions before and after each chunk; return `Retry` on churn.

- [ ] **Step 5: Install the transport behind a private runtime facade**

Expose a cloneable transport handle from the HVPatch engine at carrier setup,
store it privately in `ProcessContext`, and implement:

```rust
impl MmAccessAuthority {
    pub fn read_foreign(
        &self,
        mm: &ForeignMm,
        range: MmReadRange<'_>,
        dst: &mut [u8],
    ) -> Result<ForeignReadReceipt, MmAccessError>;
}
```

The facade alone projects HAL snapshots and retries churn with a fixed
attempt/deadline budget.

- [ ] **Step 6: Run focused gates and commit**

```bash
RUSTC_WRAPPER= cargo test -p carrick-hal foreign_mm
RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf foreign_mm
RUSTC_WRAPPER= cargo test -p carrick-runtime kernel::mm_access
RUSTC_WRAPPER= cargo test -p carrick-runtime hvpatch
```

```bash
git add crates/carrick-hal crates/carrick-vmm-hvf crates/carrick-aarch64 \
  crates/carrick-runtime
git commit -m "feat(hvpatch): add carrier-owned foreign MM reads"
```

Request independent review before consumer migration.

---

### Task 6: Structural `PtPause -> HostAlias` Mutation Authority

**Files:**
- Create: `crates/carrick-runtime/src/dispatch/mm_mutation.rs`
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs`
- Modify: `crates/carrick-runtime/src/dispatch/mem.rs`
- Modify: `crates/carrick-runtime/src/runtime.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/quiesce.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/executor.rs`
- Modify: `crates/carrick-vmm-hvf/src/trap.rs`
- Delete: `crates/carrick-runtime/src/dispatch/lock_order.rs`

**Interfaces:**
- Consumes: existing page-table pause/exclusive guards and host-alias transaction.
- Produces: non-cloneable `MmMutationGuard`, borrowed `HostAliasPermit`, and permit-requiring alias entry points.

- [ ] **Step 1: Write RED construction/lifetime tests**

Add source/compile contracts proving `HostAliasPermit` cannot be constructed,
cloned, or returned beyond its `MmMutationGuard`. Add a runtime concurrency
test that holds alias work and verifies another thread never waits for page-
table exclusion from inside that phase.

- [ ] **Step 2: Implement the outer guard and inner permit**

Use private fields and a borrow-bound permit:

```rust
pub struct MmMutationGuard { pt_pause: PtPauseAuthority, mm: MmId }
pub struct HostAliasPermit<'guard> {
    mm: MmId,
    _guard: PhantomData<&'guard mut MmMutationGuard>,
}

impl MmMutationGuard {
    pub fn host_alias_permit(&mut self) -> HostAliasPermit<'_>;
}
```

The threaded run loop passes its real `PtPauseGuard` or `Stage1Exclusive`
authority into the only threaded constructor. Non-threaded dispatch uses a
separate sealed single-executor constructor at its outer boundary. Both create
the guard before calling the dispatcher; no handler can call either
constructor. The permit has no constructor outside the module.

- [ ] **Step 3: Thread the guard through every dispatch context**

Add `mm_mutation: &'a mut MmMutationGuard` to `SyscallCtx`. Construct it at the
threaded and non-threaded outer dispatch boundaries and pass it through
dispatch, restart, and completion paths. Update focused test contexts through
the test-only single-executor issuer, not a public `Default`.

- [ ] **Step 4: Require the permit at every real alias acquisition**

Change `HostAliasTransactions::begin_dispatch`,
`DispatchMmBinding::begin_dispatch`, and public dispatcher entry points to
accept `&HostAliasPermit`. Thread the permit through mmap install, rollback,
COW, and cleanup paths. Read-only VMA snapshots do not enter the alias phase.

- [ ] **Step 5: Remove the dead validator and fake acquisition calls**

Delete `dispatch/lock_order.rs`, its module declaration, executor
`LockOrderGuard::acquire(LockLevel::Proc)` calls, and
`executor_boundary_is_clear`. Replace the boundary check with an assertion on
the real mutation/alias coordinator state only where needed for correctness.

- [ ] **Step 6: Prove the structural source gate is green**

```bash
python3 scripts/migrate/check-mm-authority.py --self-test
python3 scripts/migrate/check-mm-authority.py --check
RUSTC_WRAPPER= cargo test -p carrick-runtime mm_mutation
RUSTC_WRAPPER= cargo test -p carrick-runtime dispatch::mem::tests --lib
RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf frame_cow
```

Expected: no `unpermitted-host-alias` or `legacy-lock-order` finding and no
deadlock watchdog expiry.

- [ ] **Step 7: Commit and request independent concurrency review**

```bash
git add crates/carrick-runtime crates/carrick-vmm-hvf \
  scripts/migrate/check-mm-authority.py
git commit -m "refactor(runtime): make MM mutation lock order structural"
```

---

### Task 7: Foreign COW/Write and `CowBroken`

**Files:**
- Modify: `crates/carrick-hal/src/foreign_mm.rs`
- Modify: `crates/carrick-runtime/src/kernel/mm_access.rs`
- Modify: `crates/carrick-runtime/src/hvpatch/mod.rs`
- Modify: `crates/carrick-runtime/src/dispatch/mm_mutation.rs`
- Modify: `crates/carrick-vmm-hvf/src/trap.rs`

**Interfaces:**
- Consumes: `ForeignMm`, `MmWriteRange`, carrier `MmAccessState`, and structural mutation authority.
- Produces: transactional `break_cow`, opaque `CowBroken`, and receipt-consuming foreign writes.

- [ ] **Step 1: Add RED COW identity and rollback tests**

Test a forked parent/child mapping at the same VA. Foreign-write the child and
assert parent bytes remain unchanged. Reject a receipt applied to the parent,
another range, an advanced revision, or a recycled owner generation.

Inject failure after reservation, stage-2 map, stage-1 edit, invalidation, and
inventory preparation. Every reversible failure must restore the original
stage-1 image and owner; the kernel inventory must match the pre-state.

- [ ] **Step 2: Extend the HAL transport without exposing safe authority**

Add `break_cow` and `write` with `ForeignCowReceipt` and
`ForeignMmWriteReceipt`. Receipt constructors remain backend-private; getters
expose MM/range/revision/mapping/frame/owner values for runtime validation.

- [ ] **Step 3: Factor existing COW over `MmAccessState`**

Move only MM-owned COW inputs out of the current engine. Reuse the existing
transaction phases and rollback pre-image. Borrow the pre-dispatch
`MmMutationGuard`, mint the host-alias permit, mutate/publish under that order,
and invalidate the target ASID from the shared carrier invalidator. The backend
must not reacquire page-table exclusion.

- [ ] **Step 4: Mint and consume `CowBroken` in the runtime facade**

Implement:

```rust
pub fn break_foreign_cow<'mm>(
    &self,
    mutation: &mut MmMutationGuard,
    mm: &'mm ForeignMm,
    range: MmWriteRange<'mm>,
) -> Result<CowBroken<'mm>, MmAccessError>;

pub fn write_foreign(
    &self,
    witness: CowBroken<'_>,
    src: &[u8],
) -> Result<ForeignWriteReceipt, MmAccessError>;
```

Validate exact token, range, three revisions, and owner generation before
minting and again before copying. Consume one witness per COW compound/chunk.

- [ ] **Step 5: Pass focused COW and MM authority gates**

```bash
RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf foreign_cow
RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf frame_cow
RUSTC_WRAPPER= cargo test -p carrick-runtime kernel::mm_access
RUSTC_WRAPPER= cargo test -p carrick-runtime hvpatch::
python3 scripts/migrate/check-mm-authority.py --check
```

- [ ] **Step 6: Commit and independently review the transaction**

```bash
git add crates/carrick-hal crates/carrick-runtime crates/carrick-vmm-hvf
git commit -m "feat(hvpatch): require COW witness for foreign MM writes"
```

The reviewer must inspect every irreversible boundary and construct a concrete
wrong-MM or rollback failure scenario before approval.

---

### Task 8: Antigravity File-Disjoint Consumer Migrations

**Files:**
- Worker A: `crates/carrick-runtime/src/dispatch/proc.rs` process-vm section and tests
- Worker B: `crates/carrick-runtime/src/dispatch/proc.rs` ptrace section and tests, serialized after Worker A because the file overlaps
- Worker C: `crates/carrick-runtime/src/vfs/proc.rs`, `crates/carrick-runtime/src/dispatch/fs.rs`, open-description/token plumbing files approved in its brief

**Interfaces:**
- Consumes: canonical `MmRelation`, token ranges, `MmAccessAuthority`, and `CowBroken` APIs from Tasks 3-7.
- Produces: correct process-vm, ptrace PEEK/POKE, and retained `/proc/<pid>/mem` read/write behavior.

- [ ] **Step 1: Add Codex-owned consumer contract tests before delegation**

Add integration tests that prove:

```text
process_vm_readv: child bytes, partial fault count, PROT_NONE EFAULT
process_vm_writev: child changes, parent COW peer unchanged, partial count
ptrace PEEK/POKE: exact word, invalid address EIO, stale target ESRCH
proc mem: foreign read/write, retained old MM across exec, secret range EIO
```

Run them against the canonical pre-consumer code and record their exact
EFAULT/ENOSYS/open-refusal failures.

- [ ] **Step 2: Delegate process-vm migration**

Launch `agy/mm-process-vm` in an isolated worktree. Scope it to the process-vm
functions/tests only. It must preserve permission checks, PID-zero semantics,
iovec import ordering, shared-MM current routing, partial transfer, and errno
mapping. Required gates:

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime dispatch::proc::tests::process_vm
python3 scripts/migrate/check-mm-authority.py --path crates/carrick-runtime/src/dispatch/proc.rs
```

Codex reviews and returns any wrong-MM, COW, or partial-count defect to the same
conversation before integration.

- [ ] **Step 3: Delegate ptrace migration on the updated canonical base**

Launch `agy/mm-ptrace` only after Worker A is canonical. Scope it to HVPatch
PEEK/POKE and focused tests. It must retain kernel ptrace relationship checks,
request-specific `EIO`, and `ESRCH`; it may not route through host ptrace in the
HVPatch arm.

- [ ] **Step 4: Delegate proc-mem plumbing independently**

Launch `agy/mm-proc-mem` on the exact canonical API commit. The open description
must retain `MmToken` rather than PID, and read/write must use that token after
target exec. It may not broaden synthetic proc path handling or alter unrelated
VFS state.

- [ ] **Step 5: Integrate only reviewed patches and run the combined contracts**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime process_vm
RUSTC_WRAPPER= cargo test -p carrick-runtime ptrace
RUSTC_WRAPPER= cargo test -p carrick-runtime proc_mem
RUSTC_WRAPPER= cargo test -p carrick-runtime --test syscall_process
python3 scripts/migrate/check-mm-authority.py --check
```

- [ ] **Step 6: Commit canonical consumer migrations**

Use separate commits so each review receipt stays attributable:

```bash
git commit -m "feat(runtime): route process-vm through foreign MM authority"
git commit -m "feat(runtime): route ptrace memory through foreign MM authority"
git commit -m "feat(runtime): retain MM authority in proc mem files"
```

---

### Task 9: Red/Green Embed Probe and Conformance Closure

**Files:**
- Modify: `conformance-probes/src/lib.rs`
- Modify: `conformance-probes/probe-inventory.json`
- Modify: one `crates/carrick-conformance-next/tests/probes_shard_*.rs` selected by inventory balance
- Modify: source-hash-validated oracle fixture generated by the conformance-next workflow
- Modify: `scripts/conformance/closure-scope.json` only if the exact LTP rows become gating

**Interfaces:**
- Consumes: public syscall behavior through `carrick-embed`.
- Produces: `foreignmmmatrix` coverage for read/write/COW/ptrace/proc-mem semantics plus authoritative LTP receipts.

- [ ] **Step 1: Add one deterministic generic probe**

`foreignmmmatrix` forks a child and exchanges exact addresses over a pipe. It
emits stable lines for process-vm read, process-vm write with parent/child COW
separation, ptrace PEEK/POKE, proc-mem read/write, retained proc-mem across exec,
PROT_NONE, secret-memory, partial iovec, and stale-target cases. No timing text,
host PID, or random bytes enter output.

- [ ] **Step 2: Refresh only the probe's Docker oracle**

Run the repository's source-hash oracle command for `foreignmmmatrix` in a
Docker-only phase. Record the source hash and exact line count. Do not run a
Carrick guest concurrently.

- [ ] **Step 3: Prove RED against the pre-consumer signed artifact**

Build/sign the parent commit before Task 8, run only `foreignmmmatrix`, and
record DIFF lines showing honest EFAULT/ENOSYS/proc refusal. A SKIP or empty
selection is failure.

- [ ] **Step 4: Prove GREEN against the exact current artifact**

```bash
RUSTC_WRAPPER= just build
CARRICK_PROBE_FILTER=foreignmmmatrix RUSTC_WRAPPER= just conformance-probes
```

Expected: exactly one selected probe and `MATCH`; record source HEAD, binary
SHA-256, CDHash, LC_UUID, entitlement, `__dof_carrick`, and scoped cleanup.

- [ ] **Step 5: Run the three LTP rows serially through the harness**

Run Carrick first, then use the source-hash-validated cached Docker oracle for:

```text
ltp-process_vm_readv02
ltp-process_vm_readv03
ltp-process_vm_writev02
```

Expected Carrick totals: 1/1, 32/32, and 2/2 pass respectively, matching the
authoritative arm64 oracle. Read both `.out` and `.err` with `grep -a`.

- [ ] **Step 6: Commit probe and truthful gate changes**

```bash
git add conformance-probes crates/carrick-conformance-next \
  scripts/conformance/closure-scope.json
git commit -m "test(conformance): gate foreign MM memory semantics"
```

Do not bulk re-bless unrelated rows.

---

### Task 10: Full Closure, Independent Review, Receipt, and Main Fast-Forward

**Files:**
- Modify: `docs/identity-and-scope-domains.md`
- Modify: `docs/runtime-abstraction-audit-2026-08-27.md`
- Modify: `.superpowers/sdd/2026-08-28-mm-authority-lock-order/progress.md` (ignored controller ledger)

**Interfaces:**
- Consumes: all prior commits and exact signed receipts.
- Produces: zero source findings, full repository verification, independent approvals, audit closure for ownership/lock-order items, and exact local-main integration.

- [ ] **Step 1: Run source and structural completion census**

```bash
python3 scripts/migrate/check-mm-authority.py --self-test
python3 scripts/migrate/check-mm-authority.py --check
rg -n 'ForeignMmAccess|LockLevel|LockOrderGuard|process_vm_copy_self' crates/carrick-runtime/src
rg -n 'GuestMemory for' crates --glob '*.rs'
```

Expected: checker zero production findings; legacy authority/validator names
absent; any broad-search matches are enumerated and classified.

- [ ] **Step 2: Run focused and repository gates**

```bash
RUSTC_WRAPPER= just fmt-check
RUSTC_WRAPPER= just clippy
RUSTC_WRAPPER= just lint-domains
RUSTC_WRAPPER= just doc
RUSTC_WRAPPER= just deny
RUSTC_WRAPPER= just check-matrix
RUSTC_WRAPPER= just check --workspace
RUST_TEST_THREADS=1 RUSTC_WRAPPER= just test
RUST_TEST_THREADS=1 RUSTC_WRAPPER= just test-integration
RUST_TEST_THREADS=1 RUSTC_WRAPPER= just test-embed foreignmmmatrix
```

Run unrestricted only where the documented compiler/USDT host integration
requires it. Do not rebaseline a position-only host-authority drift with
`changed=[]`.

- [ ] **Step 3: Request two independent reviews**

Reviewer A owns token/range/revision/consumer semantics and must construct
wrong-MM, PID-reuse, exec, partial-transfer, and stale-receipt scenarios.
Reviewer B owns shared HVPatch state, COW rollback, target invalidation,
structural lock order, hot-path cost, source-gate coverage, and receipts.
Resolve every actionable finding; Antigravity-owned defects return to the same
worker conversation before Codex integrates the repair.

- [ ] **Step 4: Write exact completion receipts**

Mark ownership and lock-order rows closed only after both reviews and gates.
Record commits, worker conversations/turn counts, corrections, source census,
test counts, signed binary identity, red/green probe evidence, LTP totals,
cleanup, and remaining audit items. If another audit item remains, say so and
continue rather than claiming full completion.

- [ ] **Step 5: Commit receipts and verify a clean canonical branch**

```bash
git add docs/identity-and-scope-domains.md \
  docs/runtime-abstraction-audit-2026-08-27.md
git commit -m "docs(runtime): close MM authority and structural lock order"
git status --short
git diff --check main...HEAD
```

- [ ] **Step 6: Fast-forward local main and prove exact ancestry**

From `/Volumes/CaseSensitive/carrick`:

```bash
git status --short
git merge --ff-only codex/fd-description-seam
git rev-list --left-right --count main...codex/fd-description-seam
git merge-base --is-ancestor codex/fd-description-seam main
```

Expected: clean status, `0 0`, and ancestor exit 0. Do not push.

- [ ] **Step 7: Scoped cleanup**

Run `agy_worker.py reap` with only this milestone's `AGY_RUN_ID`, remove clean
integrated worker worktrees/branches, and retain the canonical worktree until
the full runtime-abstraction audit completion audit proves no required item
remains.
