# Task 7 report — foreign COW/write and `CowBroken`

## Status

DONE. Task 7 now provides the canonical end-to-end foreign-write API: an exact
foreign-MM/range lease is converted into an opaque, single-use `CowBroken`
witness under a real target-MM `MmMutationGuard`, and `write_foreign` consumes
that witness only after revalidating the complete post-COW identity. The HVF
backend reuses the production frame-COW transaction and rollback pre-image and
does not reacquire page-table exclusion.

The director-selected exact-target invalidation design is implemented as a
two-phase pause/publication handshake. Target-active executors leave guest and
close admission, service the published exact-ASID generation on their owner
vCPU, acknowledge it, and remain excluded. Inactive/resident executors retain
the generation and must service it before the next guest entry with that exact
MM binding. The admission barrier stays raised through edit, invalidation,
inventory commit, and rollback.

## Base, workspace, and scope

- Worktree:
  `/Volumes/CaseSensitive/carrick/.worktrees/fd-description-seam`
- Branch: `codex/fd-description-seam`
- Required base and observed initial HEAD:
  `c3f56790095282c31128ac225cedddd4e3bd4a07`
- Commit message requested by the brief:
  `feat(hvpatch): require COW witness for foreign MM writes`
- No guest or Docker run was started. All tests were host-only.
- No subagent or reviewer was dispatched; the controller will independently
  review the task.
- `crates/carrick-runtime/src/dispatch/proc.rs` was not edited. The production
  checker still reports exactly its one intentional Task 8
  `foreign-current-memory` finding.

## Director rulings and architectural cost

The original five-file task list did not contain enough plumbing to acquire a
real mutation guard for the resolved target MM or to invalidate an exact target
ASID without borrowing the caller's engine. The first ruling therefore made
Task 7 responsible for the narrow target-MM runtime binding and shared
invalidation endpoint. It expressly prohibited adding `process_vm_writev` to
the current-MM pre-dispatch classifier: the target exists only after syscall
resolution, and a caller-MM guard would authorize the wrong address space.

The second ruling selected a two-phase pause/publication handshake over an
async syscall continuation or a reserved maintenance vCPU:

1. Exact target-MM executors leave guest execution and close admission.
2. The COW transaction edits stage 1.
3. The coordinator publishes an exact MM/ASID/strong-generation/COW-generation
   invalidation request.
4. Every target-active participant services the request on its owner vCPU,
   acknowledges it, and stays parked.
5. The coordinator may advance to inventory commit only after those active
   acknowledgements. Missing, failed, or timed-out acknowledgements fail closed.
6. Inactive/resident workers remember the generation and must service it before
   any later guest entry under that exact target binding.
7. Rollback restores the pre-image and publishes a second invalidation phase
   before admission is released.

The cost is a larger but still narrow diff: the exact-MM pause coordinator,
stage-1 binding, executor continuation, guest-entry boundary, and HVF owner-vCPU
maintenance endpoint all participate. This avoids a one-vCPU self-command
deadlock, does not consume a permanent vCPU, does not defer the syscall through
the scheduler, and does not create a caller-engine fallback.

Both rulings and their costs are also recorded in
`.superpowers/sdd/2026-08-28-mm-authority-lock-order/progress.md`.

## Red-first evidence

### Baseline

Before Task 7 edits:

```text
RUSTC_WRAPPER= cargo test -p carrick-runtime kernel::mm_access
test result: ok. 14 passed; 0 failed
```

### HAL receipt/transport RED

The focused HAL test first called the missing `break_cow` and `write` methods
and inspected every required receipt field:

```text
RUSTC_WRAPPER= cargo test -p carrick-hal foreign_mm --no-run
exit 101
```

The compiler reported the intended missing `ForeignCowReceipt`,
`ForeignMmWriteReceipt`, transport methods, and sealed endpoint invocations.

### Runtime identity/witness RED

The runtime tests first covered parent/child same-VA separation, wrong guard MM,
another token's range, wrong receipt MM/range, each of the three independently
advanced revision domains, post-COW staleness in all three revision domains,
and a recycled owner generation:

```text
RUSTC_WRAPPER= cargo test -p carrick-runtime kernel::mm_access --no-run
exit 101
```

The compiler reported 21 intended missing API/error items, including
`ForeignMm::write_range`, `break_foreign_cow`, `write_foreign`, and the new
fail-closed validation results.

### Two-phase pause RED

The exact pause test was added before its invalidation-phase API:

```text
RUSTC_WRAPPER= cargo test -p carrick-thread \
  exact_mm_invalidation_phase_keeps_admission_closed_until_acknowledged --no-run
exit 101
```

The compiler reported ten intended missing phase/ticket/publication/acknowledge
items.

### Resident-generation and guest-entry RED

Stage-1 ledger tests first referred to the missing exact generation ticket and
resident pending/service API:

```text
RUSTC_WRAPPER= cargo test -p carrick-runtime \
  exact_stage1_invalidation_generation_is_required_before_reentry --no-run
exit 101
```

The compiler reported eleven intended missing items. A separate guest-entry
test was RED on missing `service_pending_cow_invalidation`; it proves the gate
belongs on every entry, not merely when a task is loaded onto an executor.

### Backend transaction sensitivity RED

The backend tests were added while resuming a partially implemented production
transaction. To prove that the tests detect absence of the COW path, I
temporarily disabled the transaction under `cfg(test)` and ran:

```text
CARRICK_TEST_DISABLE_FOREIGN_COW=1 RUSTC_WRAPPER= \
  cargo test -p carrick-vmm-hvf foreign_cow
exit 101; 0 passed; 3 failed
```

The failures were the intended `AuthorityUnavailable`/missing invalidation and
rollback results. The temporary mutation hook was then removed. This is an
explicit test-sensitivity RED captured after resuming the partial function, not
a claim that it chronologically preceded every production line.

## Implemented authority and transaction

### Runtime facade

`ForeignMm::write_range` binds the requested subrange to the existing exact
foreign-MM capability. `with_foreign_mutation` obtains a guard only through the
retained exact dispatch-MM binding; it cannot manufacture a guard from an MM
key. The canonical facade is:

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

Before COW, runtime authenticates exact guard MM, foreign token owner, range,
all three revision domains, mapping identity, frame identity, and host owner
generation. It validates the backend receipt against the same authority before
minting opaque `CowBroken`. `write_foreign` consumes the witness and revalidates
the complete post-COW receipt, including all three post-COW revisions and the
new owner generation, before copying bytes. A witness cannot be cloned or
reused.

HAL receipts are data-only traits. The safe endpoint functions and all concrete
receipt constructors remain sealed/backend-private; the runtime receives no
pause constructor, engine, or raw transport mutation authority.

### Exact target binding and fork/exec/`CLONE_VM`

The MM-owned `MmAccessState` retains the exact COW runtime identity, authority,
stage-1 scope, and rollback scratch. Kernel `Mm` retains a sealed exact
dispatch mutation binding, published with its existing process/MM binding.
Shared `CLONE_VM` tasks retain the same MM/runtime binding. Copied fork MMs get
their own identity and COW state. Exec replacement publishes the replacement
MM's binding rather than looking up authority by caller or current executor.

### Two-phase exact-ASID invalidation

`PtQuiesce` now distinguishes the initial out-of-guest pause from the published
invalidation phase. A request carries the exact MM key, ASID, strong generation,
and monotonic COW generation. The pause records the exact set of active target
participants; each callback runs without the coordinator lock, executes TLBI on
that participant's owner vCPU, then acknowledges or records failure while the
participant remains parked. Publication waits only for the exact active set and
uses the existing overall deadline. Timeout, missing acknowledgement, callback
failure, or identity mismatch fails closed.

The stage-1 lease owns the generation ledger and resident-executor pending set.
Inactive workers do not participate in the synchronous acknowledgement count;
instead, the latest exact generation supersedes older pending generations and
must be serviced at the mandatory pre-entry boundary. Immediate service is
permitted when the owner engine is already available. A worker running another
MM never receives a synchronous self-command for the target.

The HVF endpoint invalidates only through the already loaded owner vCPU and the
carrier maintenance root. It never reacquires PtPause, detaches the target MM,
or waits from a host-alias phase back toward PtPause.

### Production COW transaction and rollback

The backend uses the production inventory split, stage, kernel-commit, and
backend-commit helpers plus the full existing `rollback_pre_image`:

1. Authenticate the exact MM runtime identity and requested snapshot.
2. Under the borrowed exact mutation guard, enter host-alias authority and keep
   admission excluded for the entire transaction.
3. Reserve a replacement global frame and copy the old frame contents.
4. Map/register the replacement owner, retaining RAII cleanup for every early
   return.
5. Prepare the inventory mutation and edit the exact target stage-1 leaf.
6. Publish/wait for the exact-ASID invalidation phase.
7. Apply the kernel-authority inventory change, then commit backend inventory in
   the existing target-ASID ordering.
8. Re-authenticate the live stage-1 output/mapping/frame/owner and return a
   private receipt.

On any reversible failure, rollback restores the byte-exact stage-1 pre-image,
the original owner/global-owner set, kernel inventory, backend inventory, and
armed range. If stage 1 had become visible, rollback republishes the restored
image through a new exact-ASID invalidation phase before the admission barrier
is lowered. New scratch and owner reservations are retired on every error path.

## Failure-boundary self-review

| Boundary | Injected result | Required restoration proved |
|---|---|---|
| after reservation | fail | stage 1, exact inventory fingerprint, global owners, armed range |
| after stage-2 map/register | fail | new mapping/owner retired plus exact pre-state |
| after stage-1 edit | fail | byte-exact stage-1 rollback plus exact inventory/owner pre-state |
| invalidation | fail | old stage 1 restored and a rollback invalidation published |
| inventory preparation | fail | no inventory publication; exact stage1/owner/inventory pre-state |

Concrete wrong-MM scenario reviewed: a child token and parent mutation guard
refer to identical virtual addresses but different MM identities. Runtime
rejects before the HAL call because guard identity is compared to the retained
token owner, not to VA or mapping shape. A child COW/write test then proves the
parent owner frame and bytes remain unchanged.

Concrete rollback scenario reviewed: target-active TLBI fails after the new
stage-1 leaf is visible. The transaction restores the saved page-table bytes,
publishes a new invalidation generation for the restored translation, waits for
active acknowledgements while admission remains closed, restores exact
inventory/owner state, and only then releases exclusion. It never reports a
successful witness for the transient new mapping.

Additional self-review findings fixed before completion:

- Moved the resident generation service from task-load-only to every guest
  entry so a continuing exact-MM task cannot bypass a pending invalidation.
- Added the exact same-MM nested path so the foreign facade cannot deadlock by
  commanding its own currently held target pause.
- Allowed `finish_invalidation` to close one failed phase and publish rollback
  while keeping the admission barrier raised.
- Ensured every stage-1 early error recycles scratch and retires the new owner.
- Added an exact `mapping_is_live` check before the final COW receipt.
- Kept narrowly documented dead-code allowances only for the canonical Task 8
  consumer seam; no checker finding was masked or reclassified.
- Removed the temporary backend test mutation hook and scanned for its name.

## Files changed and why

The five brief-listed files:

- `crates/carrick-hal/src/foreign_mm.rs`: data-only COW/write receipts, borrowed
  invalidator, sealed transport calls, and focused receipt test.
- `crates/carrick-runtime/src/kernel/mm_access.rs`: range API, exact validation,
  opaque `CowBroken`, canonical COW/write facade, and authority tests.
- `crates/carrick-runtime/src/hvpatch/mod.rs`: install exact HVPatch MM runtime
  authority with the retained MM binding.
- `crates/carrick-runtime/src/dispatch/mm_mutation.rs`: acquire/lend a real
  target-MM mutation guard through the exact dispatcher authority.
- `crates/carrick-vmm-hvf/src/trap.rs`: MM-owned COW state, private receipts,
  production transaction/rollback, writes, failpoints, and focused tests.

Narrow extra files authorized by the rulings:

- `crates/carrick-hal/src/lib.rs`: export the new data-only transport traits.
- `crates/carrick-runtime/src/dispatch/mod.rs`: publish the exact mutation
  binding alongside the existing process/MM binding.
- `crates/carrick-runtime/src/hvpatch/stage1_mm.rs`: exact generation ledger,
  resident pending set, and pre-entry ticket/service rules.
- `crates/carrick-runtime/src/kernel/guest_execution.rs`: retain exact executor
  identity needed by the target-MM binding.
- `crates/carrick-runtime/src/kernel/mod.rs`: export only the opaque runtime
  witness/receipt API needed by the later consumer.
- `crates/carrick-runtime/src/kernel/objects.rs`: store the sealed exact-MM
  mutation binding and preserve fork/exec/`CLONE_VM` identity.
- `crates/carrick-runtime/src/vcpu_loop/continuation.rs`: carry exact executor
  and binding state across continuation return.
- `crates/carrick-runtime/src/vcpu_loop/executor.rs`: thread exact resident
  executor identity into each quantum.
- `crates/carrick-runtime/src/vcpu_loop/mod.rs`: invoke the mandatory generation
  service at every guest-entry boundary.
- `crates/carrick-runtime/src/vcpu_loop/quiesce.rs`: exact target pause,
  active-owner service/ack callbacks, and same-MM nested handling.
- `crates/carrick-thread/src/fork_quiesce.rs`: two-phase publication state,
  exact participant accounting, deadline/failure handling, and tests.
- `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs`: owner-vCPU loaded-ASID TLBI
  endpoint with no pause reacquisition.
- `.superpowers/sdd/2026-08-28-mm-authority-lock-order/progress.md`: record both
  director rulings, their cost, and the Task 7 completion receipt.

## GREEN verification

Focused gates:

```text
RUSTC_WRAPPER= cargo test -p carrick-hal foreign_mm
1 passed

RUSTC_WRAPPER= RUST_TEST_THREADS=1 cargo test -p carrick-runtime kernel::mm_access
18 passed

RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf foreign_cow
3 passed

RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf frame_cow
1 passed

RUSTC_WRAPPER= RUST_TEST_THREADS=1 cargo test -p carrick-runtime hvpatch::
109 passed

RUSTC_WRAPPER= cargo test -p carrick-thread exact_mm_invalidation_phase
2 passed

RUSTC_WRAPPER= cargo test -p carrick-runtime \
  exact_stage1_invalidation_generation_is_required_before_reentry
1 passed
```

Broad proportional host gates:

```text
RUSTC_WRAPPER= RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib
2090 passed

RUSTC_WRAPPER= RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib
279 passed

RUSTC_WRAPPER= cargo test -p carrick-thread --lib
53 passed

RUSTC_WRAPPER= cargo check --workspace --all-targets
green

RUSTC_WRAPPER= cargo clippy -p carrick-hal -p carrick-thread \
  -p carrick-runtime -p carrick-vmm-hvf --all-targets -- -D warnings
green
```

Authority checker:

```text
python3 scripts/migrate/check-mm-authority.py --self-test
20 negative fixtures and 17 positive fixtures passed

python3 scripts/migrate/check-mm-authority.py --check
exit 1; exactly one production finding:
crates/carrick-runtime/src/dispatch/proc.rs:4425: foreign-current-memory
```

The production checker result is the exact intentional Task 8 finding required
by the brief. Task 7 did not edit `proc.rs` and did not suppress, reclassify, or
otherwise mask it.

Final hygiene gates are `cargo fmt --all -- --check`, `git diff --check`, an
empty `dispatch/proc.rs` diff, absence of the temporary mutation hook, and a
clean post-commit worktree. Their fresh results are recorded in the completion
message and progress receipt.

## Concerns and deferred work

- The one production checker finding in `dispatch/proc.rs` is intentionally
  deferred to Task 8, which now has the canonical end-to-end API to consume.
- Task 7 deliberately does not wire the `process_vm_writev` syscall consumer;
  doing so here would cross the task boundary and risk inventing a second
  authority path.
- No guest/HVF-creation or Docker workload run was necessary or performed; the
  broad HVF crate tests exercise the host-side transaction and rollback path
  without launching a guest.
