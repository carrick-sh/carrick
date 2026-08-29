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

## Fix Round 1 (review of `1bef8eb51948a4e97c5e521e686a99a936b62c3b`)

This round repairs all six findings from the independent rejection. It also
retains the director's alternative-(1) ruling: exact-target executors pause
first, the COW edit publishes a typed exact-stage-1 invalidation second, active
owner vCPUs acknowledge while remaining excluded, and inactive residents
service the published generation at mandatory pre-entry. The cost remains an
atomic generation pair and retained per-resident observer on the ordinary
entry path, plus a mutex slow path only when the generations differ. No async
continuation, maintenance vCPU, caller-engine fallback, `proc.rs` change, or
HostAlias-to-PtPause reacquisition was introduced.

### RED evidence captured against the rejected implementation

The focused regressions were installed before their fixes and run against the
rejected shape:

```text
RUSTC_WRAPPER= cargo test -p carrick-runtime \
  production_composition_foreign_cow_does_not_reacquire_snapshot_under_alias -- --nocapture
FAILED: production composition returned Err(ForeignWriteTimedOut)
0 passed; 1 failed; 2090 filtered out

RUSTC_WRAPPER= cargo test -p carrick-runtime \
  foreign_cow_rejects_wrong_mapping_frame_physical_range_and_current_owner
FAILED: expected ForeignCowReceiptMismatch

RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf \
  foreign_cow_commit_cannot_be_reported_as_retryable_by_final_snapshot_contention
FAILED: committed COW returned Err(TimedOut)

RUSTC_WRAPPER= cargo test -p carrick-runtime \
  no_work_current_mm_reentry_never_enters_cow_invalidation_slow_path
FAILED: expected slow-path count 0, observed 1

RUSTC_WRAPPER= cargo test -p carrick-thread \
  pt_pause_exact_identity_does_not_accept_recycled_asid_with_new_root --no-run
FAILED to compile: the typed ASID generation, stage-1 identity, COW generation,
and exact invalidation request APIs did not exist (11 type/API errors)
```

### Finding 1 — production foreign COW self-timeout

The runtime now authenticates the complete backend/VMA/inventory snapshot
before entering `with_host_alias`. The HAL `break_cow` transport method no
longer receives `ForeignMmLiveAuthority`, so the backend cannot reacquire the
snapshot reader while alias publication is active. The concrete carrier COW
transaction consumes only the pre-authenticated snapshot and the borrowed
invalidator. Runtime validates the returned receipt after alias release while
the exact-MM mutation guard still owns page-table exclusion.

Covering production-shape tests use the real `Stage1MmBackend`,
`DispatchMmAuthority`, VMA source, mutation coordinator, executor census,
stage-1 lease, and host-alias/pause facade. The carrier transaction is covered
in the HVF crate with the real `CarrierForeignMmTransport` and retained
`MmAccessState`; the dependency direction prevents importing that concrete
transport back into runtime, so the cross-crate seam is exercised on both
sides rather than by inventing a second production authority constructor.

```text
RUSTC_WRAPPER= cargo test -p carrick-runtime production_composition_
4 passed: success, final-snapshot contention, CLONE_VM, exec/retirement

RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf foreign_cow
4 passed, including real carrier transport COW success and rollback
```

### Finding 2 — recoverable work after irreversible inventory publication

`FrameCowAuthority::apply_with_receipt` now performs the inventory apply and
returns the exact authenticated post-commit MM/revision/mapping set in the same
kernel-owner operation. The backend retains the reservation challenge and
authenticates the apply receipt before proceeding. It derives the final carrier
snapshot from that receipt and the already authenticated pre-commit domains.
After the successful apply boundary, every impossible mapping, inventory,
stage-1, or owner postcondition fail-stops; there is no recoverable snapshot
call or `?`. The carrier additionally proves the exact mapping/frame/physical
extent against kernel authority and the exact owner generation/pointer against
the live owner directory before rollback is disarmed.

```text
RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf \
  foreign_cow_commit_cannot_be_reported_as_retryable_by_final_snapshot_contention
1 passed

RUSTC_WRAPPER= cargo test -p carrick-runtime \
  production_composition_committed_cow_ignores_final_snapshot_contention
1 passed
```

### Finding 3 — ordinary entry took the invalidation mutex

`Stage1MmLease` publishes the latest COW invalidation generation through an
`Arc<AtomicU64>`. Each loaded resident retains its own observed
`Arc<AtomicU64>` in `HvpatchPersistentExecutor` and passes that opaque observer
through the quantum control. Ordinary current-MM entry compares only those two
atomics. The resident map/mutex, ticket lookup, allocation, and hardware/vtable
callback occur only after a generation mismatch. Checked increments now
fail-stop on generation exhaustion rather than wrapping into an old identity.

```text
RUSTC_WRAPPER= cargo test -p carrick-runtime \
  no_work_current_mm_reentry_never_enters_cow_invalidation_slow_path
1 passed; asserted 0 slow paths and 0 hardware/vtable calls
```

### Finding 4 — raw, swappable invalidation identity domains

HAL now carries opaque `ForeignAsidGeneration`, `ForeignStage1Identity`,
`ForeignCowInvalidationGeneration`, and
`ForeignCowInvalidationIdentity`. `PtInvalidationRequest`, publication state,
participant ledger, executor matching, and acknowledgements carry those types
end-to-end, including exact MM, binding, root, ASID, ASID lifetime, and COW
publication. No raw MM/ASID/generation tuple remains in the pause ledger or
acknowledgement path. A compile-fail doctest rejects swapping an ASID generation
for a COW generation, and a host test proves a recycled numeric ASID with a new
root/generation cannot service the old request.

```text
RUSTC_WRAPPER= cargo test -p carrick-hal
111 unit tests passed; 2 compile-fail doctests passed

RUSTC_WRAPPER= cargo test -p carrick-thread \
  pt_pause_exact_identity_does_not_accept_recycled_asid_with_new_root
1 passed
```

### Finding 5 — receipt did not authenticate the live mapping/owner

The concrete carrier receipt now carries a backend-private live-inventory
receipt. Before minting `CowBroken`, runtime compares its exact MM, inventory
revision, mapping, frame, physical base, physical length, and owner generation
with every corresponding outer receipt field; it also checks range coverage
and physical overflow. `write_foreign` re-snapshots the retained exact MM,
revalidates all three revisions and mapping membership, rechecks every sealed
live-inventory domain, then lets the transport verify the still-current owner
before copying. Wrong mapping, wrong frame, wrong physical base/length, and
wrong/recycled owner all fail before witness minting or copy.

```text
RUSTC_WRAPPER= cargo test -p carrick-runtime \
  foreign_cow_rejects_wrong_mapping_frame_physical_range_and_current_owner
1 passed (all five injected receipt mismatches rejected)

RUSTC_WRAPPER= cargo test -p carrick-runtime kernel::mm_access
23 passed, including stale three-domain revision and recycled-owner write tests
```

### Finding 6 — missing production composition and topology coverage

The runtime production-shape fixture uses the real target-MM backend, dispatch
VMA authority, mutation coordinator, executor census, stage-1 lease, and exact
foreign mutation binding. The HVF fixture uses the production carrier
transport, retained `MmAccessState`, transaction, pre-image, inventory split,
owner directory, and write path. The two-phase tests use the real `PtQuiesce`,
`ForeignMmMutationAuthority`, `Stage1MmLease`, executor census, and
`HostCondvarScheduler` at budget one. Coverage includes success, full
occupancy, active target acknowledgement, inactive caller residency and
pre-entry service, caller-worker self-wait avoidance, CLONE_VM, target exec and
retirement, exact ASID/root reuse, parent/child COW separation, and every
reversible transaction boundary.

```text
RUSTC_WRAPPER= cargo test -p carrick-runtime \
  foreign_cow_active_target_acks_then_inactive_caller_resident_defers_to_reentry
1 passed

RUSTC_WRAPPER= cargo test -p carrick-runtime \
  foreign_cow_vcpu_budget_one_full_occupancy_never_waits_on_caller_worker_self_ack
1 passed

RUSTC_WRAPPER= cargo test -p carrick-runtime production_composition_
4 passed

RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf foreign_cow
4 passed; exact stage-1/inventory/owner rollback fingerprint restored at each
injected boundary
```

### Fix-round files and architectural cost

- `crates/carrick-hal/src/foreign_mm.rs`, `src/lib.rs`, and `src/threaded.rs`:
  typed invalidation identities, sealed receipt observation, removal of live
  snapshot authority from COW transport, and authenticated inventory apply.
- `crates/carrick-runtime/src/kernel/mm_access.rs`: pre-alias authentication,
  receipt-only post-commit validation, exact live-inventory checks, and
  production-shape facade tests.
- `crates/carrick-runtime/src/dispatch/mod.rs`: narrow test construction of the
  existing production dispatch/MM authority; no parallel authority path.
- `crates/carrick-runtime/src/hvpatch/stage1_mm.rs` and `src/hvpatch/mod.rs`:
  atomic published/observed fast path plus typed exact stage-1 publication.
- `crates/carrick-runtime/src/vcpu_loop/{continuation,executor,mod,quiesce}.rs`:
  retain the per-resident observer, mandatory pre-entry service, typed active
  owner acknowledgements, and production topology tests.
- `crates/carrick-thread/src/fork_quiesce.rs`: typed two-phase publication,
  participant ledger, timeout/failure accounting, and ASID/root reuse test.
- `crates/carrick-vmm-hvf/src/trap.rs`: production transaction receipt,
  post-commit fail-stop validation, exact owner proof, and carrier tests.

The added steady-state cost is two atomic loads on each HVPatch guest entry and
one retained `Arc` observer per loaded resident. Mutex/lookup/callback work is
absent until the carrier publishes a different exact-target generation.

### Fix-round GREEN verification

```text
RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf foreign_cow
4 passed
RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf frame_cow
1 passed
RUSTC_WRAPPER= cargo test -p carrick-runtime kernel::mm_access
23 passed
RUSTC_WRAPPER= RUST_TEST_THREADS=1 cargo test -p carrick-runtime hvpatch::
110 passed
RUSTC_WRAPPER= cargo test -p carrick-thread --lib
54 passed
RUSTC_WRAPPER= cargo test -p carrick-hal
111 unit + 2 compile-fail doctests passed

RUSTC_WRAPPER= RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib
2098 passed (run outside the restricted sandbox for Unix sockets/loopback)
RUSTC_WRAPPER= RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib
280 passed (run outside the restricted sandbox for ptrace child-stop)

RUSTC_WRAPPER= cargo check --workspace --all-targets
green
RUSTC_WRAPPER= cargo clippy -p carrick-hal -p carrick-thread \
  -p carrick-runtime -p carrick-vmm-hvf --all-targets -- -D warnings
green
python3 scripts/migrate/check-mm-authority.py --self-test
20 negative and 17 positive fixtures passed
python3 scripts/migrate/check-mm-authority.py --check
exit 1 with exactly the intentional Task 8 finding at
crates/carrick-runtime/src/dispatch/proc.rs:4425
cargo fmt --all -- --check
green
git diff --check
green
```

The initial sandboxed broad runtime run produced 57 `EPERM` failures for Unix
sockets, loopback binds, and scratch directories; the exact suite passed 2098/0
when rerun with normal host permissions. The initial sandboxed HVF run produced
one ptrace child-stop failure; the exact suite passed 280/0 with normal host
permissions. These are execution-environment restrictions, not retained test
failures. `progress.md` remained controller-owned and unchanged by this round;
its SHA-256 stayed
`1e7b55a97c617ca4603aecd943aa883e32cf8059203cba147e4ec20f354bcb4a`.

## Fix Round 2 (scoped review of `021e8df0b30e8f64a01c95eb9e0308493f8df5af`)

This round changes only rejected findings 5 and 6 plus the test-inventory entry
required by the new budget-one subprocess. Findings 1-4 remain unchanged. The
controller-owned `progress.md` was neither edited nor staged; its current
controller revision remained SHA-256
`dba00e46561d888848713dc9807e737fa6c524d3959a7d058693131d6e84714f`.
`dispatch/proc.rs` was not edited.

### Finding 5 — the transport's self-described receipt was not authority

#### RED

The new internally-consistent-forgery test was added before the proof change
and run against the rejected receipt-comparison implementation:

```text
RUSTC_WRAPPER= cargo test -p carrick-runtime \
  foreign_cow_rejects_internally_consistent_transport_forgery -- --nocapture
FAILED: expected ForeignCowReceiptMismatch, but the internally consistent
transport tuple minted CowBroken
0 passed; 1 failed
```

The transport could previously choose both compared getter sets. The test
varies a self-consistent mapping, frame, physical extent, and current/recycled
owner tuple; disagreement between an outer and inner copy is no longer the
test oracle.

#### GREEN and implementation

`ForeignCowLiveInventoryReceipt` is removed. `FrameCowAuthority`, which is the
runtime's exact kernel-owner binding already retained by the carrier COW
runtime, now atomically applies the inventory commit and mints an opaque
`ForeignCowKernelProof`. Its accepted payload is the runtime-private
`KernelForeignCowProof`; external transports may carry an opaque value but
cannot name or construct the accepted payload type. The payload binds the
exact `Arc<Kernel>`, MM, inventory revision, mapping, frame, physical base and
length, and owner generation.

Before minting `CowBroken`, and again before the copy, the runtime downcasts to
that private payload, checks all domains, and performs a guard-bound O(1)
lookup in the independent kernel frame inventory at the exact recorded global
revision. Replaying a valid proof with altered transport fields, another
kernel, another MM, or after any inventory publication fails closed. An
internally consistent transport-owned `Any` value has a different private
`TypeId` and is rejected. This is one extension of the existing
`FrameCowAuthority`; it does not add a parallel authority path.

```text
RUSTC_WRAPPER= cargo test -p carrick-runtime \
  foreign_cow_rejects_internally_consistent_transport_forgery -- --nocapture
1 passed; 2101 filtered out

RUSTC_WRAPPER= cargo test -p carrick-runtime kernel::mm_access
27 passed; 2075 filtered out
```

### Finding 6 — production-composed carrier/topology coverage

#### RED/sensitivity evidence

The rejected revision contained no `production_carrier_*` test or exported
carrier test-support seam. After installing the tests, a deliberate sensitivity
run disconnected `ProductionCarrierForeignCowHarness::endpoint` from its
registered production transport state while leaving the runtime fixture,
scheduler, and assertions unchanged:

```text
RUSTC_WRAPPER= cargo test -p carrick-runtime \
  production_carrier_foreign_cow_runs_end_to_end_through_runtime_facade \
  -- --nocapture
FAILED at kernel/mm_access.rs:1622:
foreign MM authority: ForeignTransport(MissingBinding)
0 passed; 1 failed; 2101 filtered out
```

Restoring the endpoint to the registered `CarrierForeignMmTransport` made the
same test green:

```text
RUSTC_WRAPPER= cargo test -p carrick-runtime \
  production_carrier_foreign_cow_runs_end_to_end_through_runtime_facade \
  -- --nocapture
1 passed; 2101 filtered out
```

This sensitivity run was temporary and fully reverted before the final gates.

#### Production composition and bounded outcomes

The feature-gated host harness owns the real `CarrierForeignMmTransport`,
`MmAccessState`, page-table image, carrier frame inventory, host-owner
directory, COW-arm ledger, aliases, and production COW transaction. Runtime
supplies the real `Stage1MmBackend`, `DispatchMmAuthority`, VMA and three-domain
snapshot sources, `KernelFrameCowAuthority`, target-MM mutation coordinator,
executor census, and facade. The carrier therefore receives the kernel-minted
mapping identities and opaque proof through the same production trait calls;
no `MockCowTransport` participates in these five tests.

The invalidation tests also use the actual process-global budgeted scheduler,
global `PtQuiesce`, exact target census, `GenericVcpuRegistry`, real
`HvpatchTaskBinding`/stage-1 resident observer, and the shared private core of
`enter_hvpatch_guest_or_service_invalidation`. The production entry wrapper
uses that same core with `invalidate_loaded_asid`; the host test wrapper changes
only the final hardware leaf to a counted callback. Consequently the automatic
inactive-resident pre-entry service and the active target acknowledgement do
not manually substitute an independent scheduler or ledger.

`vcpu_budget=1` is isolated in a child instance of the real unit-test process
so it can install the actual process-global scheduler before its `OnceLock` is
claimed. It holds the sole lease throughout the real facade/carrier COW, proves
there is no waiter or maintenance-vCPU acquisition, observes the foreign
caller resident's deferred ticket, and services it automatically on the next
exact-binding guest-entry check. The child spawn is inventoried in the existing
exact host-process-creation test.

The active target enters the real exact-MM census and registry, leaves guest on
the production kick, services and acknowledges the published generation on its
owner entry path, and stays excluded until release. CLONE_VM reaches the same
MM authority. Exec and retirement use a barrier to race actual target graph
mutation with `Kernel::foreign_mm`; the acquisition either retains the exact old
MM and completes the real carrier COW, or returns only `UnknownTask`,
`StaleContext`, or the bounded snapshot timeout. Current/wrong-MM success and
any other error panic, while scoped joins make deadlock a test failure rather
than an accepted outcome.

```text
RUSTC_WRAPPER= cargo test -p carrick-runtime production_carrier_ -- --nocapture
5 passed; 2097 filtered out

Covered scenarios:
- real facade/carrier success and authenticated write
- vCPU budget one/full occupancy and caller-worker self-ack avoidance
- active target owner acknowledgement through the shared entry core
- inactive resident mandatory automatic pre-entry service
- CLONE_VM exact authority reuse
- target exec and retirement concurrent with acquisition
```

No guest, Docker, async continuation, reserved maintenance vCPU, caller-engine
fallback, or HostAlias-to-PtPause acquisition was used.

### Round 2 files and architectural cost

- `crates/carrick-hal/src/{foreign_mm,lib,threaded}.rs`: replace the forgeable
  getter trait with an opaque proof carrier and extend the existing kernel COW
  authority's atomic apply result.
- `crates/carrick-runtime/src/kernel/{frame_inventory,mm_access}.rs`: exact
  live-at-revision lookup, retained exact kernel binding, proof validation,
  forged-tuple regression, and production-composed topology tests.
- `crates/carrick-runtime/src/vcpu_loop/{mod,quiesce}.rs`: private proof issuer
  on the existing `KernelFrameCowAuthority`, plus extraction of the production
  guest-entry core so host tests drive the exact scheduler/invalidator path.
- `crates/carrick-runtime/src/dispatch/mod.rs`: narrow test-only accessor to the
  existing dispatch MM census used by the production fixture.
- `crates/carrick-vmm-hvf/{Cargo.toml,src/trap.rs}`: opt-in host-test feature and
  real carrier transport/page-table/owner harness. The feature suppresses only
  real HVF stage-2 calls in this explicit host-test composition.
- `crates/carrick-runtime/Cargo.toml`: macOS/aarch64 dev-dependency enabling the
  VMM host-test seam; production dependency features are unchanged.
- `crates/carrick-runtime/src/runtime.rs`: exact inventory entry for the one
  isolated budget-one unit-test subprocess.

There is no new production hot-path work beyond Fix Round 1. The entry-core
extraction preserves the existing two-atomic fast path and the production
hardware leaf. Proof authentication occurs only on foreign COW/write, adds one
O(1) locked kernel-inventory point lookup, and intentionally invalidates the
witness after any intervening global inventory publication. The test-only VMM
feature and process spawn are absent from shipped consumers.

### Round 2 final verification

```text
RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf foreign_cow
4 passed; 276 filtered out
RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf frame_cow
1 passed; 279 filtered out
RUSTC_WRAPPER= cargo test -p carrick-runtime kernel::mm_access
27 passed; 2075 filtered out
RUSTC_WRAPPER= RUST_TEST_THREADS=1 cargo test -p carrick-runtime hvpatch::
110 passed; 1992 filtered out
RUSTC_WRAPPER= cargo test -p carrick-thread --lib
54 passed
RUSTC_WRAPPER= cargo test -p carrick-hal
111 unit tests and 2 compile-fail doctests passed

RUSTC_WRAPPER= RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib
2102 passed; 0 failed (normal host permissions)
RUSTC_WRAPPER= RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib
280 passed; 0 failed (normal host permissions)

RUSTC_WRAPPER= cargo check --workspace --all-targets
green
RUSTC_WRAPPER= cargo clippy -p carrick-hal -p carrick-thread \
  -p carrick-runtime -p carrick-vmm-hvf --all-targets -- -D warnings
green
python3 scripts/migrate/check-mm-authority.py --self-test
20 negative and 17 positive fixtures passed
python3 scripts/migrate/check-mm-authority.py --check
exit 1 with exactly the intentional Task 8 finding at
crates/carrick-runtime/src/dispatch/proc.rs:4425
cargo fmt --all -- --check
green
git diff --check
green
```

Self-review found no recoverable work after the irreversible carrier inventory
commit, no second snapshot acquisition under host alias, no raw invalidation
domain tuple, and no `proc.rs` diff. The only retained concern is the explicit
Task 8 production-checker finding above.
