# Task Participant Witnesses Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Carrick's remaining scalar thread-population authority with exact, purpose-specific identity witnesses while retaining `ThreadExecutionState` as the sole lifecycle authority.

**Architecture:** `Task` mints separate opaque identity sets for fork, crash, core-note coverage, crash-register polling, and non-final thread exit. `GuestExecutorCensus` becomes an identity set with RAII membership, and crash-safe-point participation becomes generation-stamped RAII so retirement cannot let a stale guard clear a successor. Codex owns these interfaces and gates; Antigravity migrates only the two file-disjoint vCPU-loop consumer groups after the interfaces land.

**Tech Stack:** Rust 2024, `parking_lot`, Python 3 source checker, Cargo/Just, Google Antigravity worker harness.

**Spec:** `docs/superpowers/specs/2026-08-28-task-participant-witnesses-design.md`

## Global Constraints

- Read `/Volumes/CaseSensitive/carrick/AGENTS.md` before every delegated task.
- Work only in `/Volumes/CaseSensitive/carrick/.worktrees/fd-description-seam` unless a task names an isolated Antigravity worktree.
- Preserve `ThreadExecutionState` as the only kernel thread run-state type.
- Every authoritative population retains exact identity; no witness exposes `usize`, `Len`, `Sub`, integer comparison, or a generic collection dereference.
- Numeric cardinality is permitted only in a method whose name ends in `_for_probe`.
- Fork and crash barrier decisions use durable `Task` membership, not executor census or vCPU registry membership.
- Stage-1 pause decisions use active/admitting executor identity, not durable `Task` membership.
- Preserve census-before-registry admission and crash-participation-before-census-removal cleanup.
- New behavior is red-first. Record the expected failure before implementation and never rewrite a test merely to make the implementation pass.
- Do not run Carrick and Docker concurrently. This milestone's default gates require no guest execution.
- Use `RUSTC_WRAPPER=` for Cargo/Just verification.
- An independently reviewed GREEN task is fast-forwarded to `main`; RED and review-pending commits are never integrated.
- Antigravity workers use dedicated manually-created worktrees, exact scope fences, and the installed `agy_worker.py`; Codex reviews actual diffs and redispatches confirmed findings to the same conversation.

---

### Task 1: Fail-Closed Scalar-Population Source Gate (RED)

**Files:**
- Create: `scripts/migrate/check-task-participant-witnesses.py`
- Modify: `justfile:128-142`

**Interfaces:**
- Consumes: production Rust leaves under `crates/carrick-runtime/src`.
- Produces: `python3 scripts/migrate/check-task-participant-witnesses.py --self-test`, `--check`, and repeatable `--path <repo-relative-file>` verification.

- [ ] **Step 1: Create the checker with executable behavioral fixtures**

Implement a comment/string-aware Rust tokenizer and scope tracker. The checker must classify `#[cfg(test)] mod`, `#[test] fn`, and nested test-only leaves as non-production. Its production findings are these exact semantic categories:

```python
FORBIDDEN_METHODS = {
    "live_thread_count": "raw task cardinality",
}

FORBIDDEN_CHAINS = {
    ("threads", "len"): "raw task membership arithmetic",
    ("threads", "count"): "raw task membership arithmetic",
}

FORBIDDEN_CENSUS_SHAPES = {
    ("GuestExecutorCensus", "AtomicUsize"): "scalar executor census storage",
    ("GuestExecutorCensus", "live", "usize"): "scalar executor census API",
}

ALLOWED_NUMERIC_METHOD_SUFFIX = "_for_probe"
```

The scanner must reject direct production calls to
`enter_crash_safe_point_participation` or
`leave_crash_safe_point_participation` outside
`kernel/guest_execution.rs` and `kernel/objects.rs`. It must accept named
`ForkBarrierParticipants`, `CrashBarrierParticipants`,
`ThreadExitParticipants`, `CrashCaptureParticipants`,
`CoreNoteParticipants`, and `participant_count_for_probe` use.

`--self-test` writes literal snippets to a temporary directory and calls the
same scanner used by `--check`. Include one negative fixture for every category
above, one negative fixture hidden behind a non-test function, and positive
fixtures for comments, strings, `#[cfg(test)]`, each named witness, and the
probe-only numeric projection. Assertions compare the literal finding category,
file, and source line; they do not grep the checker source.

- [ ] **Step 2: Prove checker fixtures pass**

Run:

```bash
python3 scripts/migrate/check-task-participant-witnesses.py --self-test
```

Expected: exit 0 and a summary naming every positive and negative fixture.

- [ ] **Step 3: Wire the checker into `lint-domains`**

Insert it after the abort ledger and before the compiler host-authority census:

```just
    python3 scripts/migrate/check-runtime-aborts.py --check
    python3 scripts/migrate/check-task-participant-witnesses.py --check
    python3 scripts/migrate/check-host-authority-transitions.py --check
```

- [ ] **Step 4: Prove the current tree is RED for the intended reason**

Run:

```bash
python3 scripts/migrate/check-task-participant-witnesses.py --check
```

Expected: non-zero with findings in `kernel/objects.rs`,
`kernel/operations.rs`, `kernel/guest_execution.rs`,
`kernel/crash_capture.rs`, `vcpu_loop/quiesce.rs`, and `vcpu_loop/mod.rs`.
Comments, string literals, and test-only assertions must not appear.

- [ ] **Step 5: Commit the RED gate**

```bash
git add scripts/migrate/check-task-participant-witnesses.py justfile
git commit -m "test(runtime): reject scalar thread population authority"
```

Do not fast-forward this RED checkpoint to `main`.

---

### Task 2: Task-Minted Witness Contract Tests (RED)

**Files:**
- Modify: `crates/carrick-runtime/src/kernel/operations.rs` test module
- Modify: `crates/carrick-runtime/src/kernel/crash_capture.rs` test module

**Interfaces:**
- Consumes: the approved method/type names from the spec.
- Produces: compile-time and behavioral pressure for exact owner authentication, purpose separation, dynamic crash membership, and final-thread refusal.

- [ ] **Step 1: Add a test fixture that creates two exact task siblings**

In the existing `operations.rs` test module, use its `bootstrap`,
`ClonePlan::from_flags(THREAD | SIGHAND | VM)`, and
`Kernel::clone_thread` fixture to produce the leader plus one sibling. Retain
both exact `ThreadKey` values. Add this exact helper beside the existing test
bootstrap:

```rust
fn clone_sibling(
    kernel: &Arc<Kernel>,
    leader: &KernelContext,
    registry_id: i32,
) -> KernelContext {
    let plan = ClonePlan::from_flags(
        LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
    )
    .expect("thread clone plan");
    kernel
        .clone_thread(
            leader,
            plan,
            ThreadId::synthetic_for_tests(registry_id),
            None,
        )
        .expect("clone sibling")
}
```

- [ ] **Step 2: Add failing fork/crash witness tests**

Add tests with these literal behavioral assertions:

```rust
#[test]
fn task_mints_distinct_fork_and_crash_sibling_witnesses() {
    let (kernel, leader) = bootstrap(19_410);
    let sibling = clone_sibling(&kernel, &leader, 19_411);

    let fork = leader
        .task()
        .fork_barrier_participants(leader.thread().key())
        .expect("exact fork owner");
    let crash = leader
        .task()
        .crash_barrier_participants(leader.thread().key())
        .expect("exact crash owner");

    assert!(fork.requires_quiesce());
    assert!(fork.contains_sibling(sibling.thread().key()));
    assert!(crash.requires_quiesce());
    assert!(crash.contains_sibling(sibling.thread().key()));
}

#[test]
fn task_participant_witness_rejects_a_stale_exact_owner() {
    let (kernel, leader) = bootstrap(19_420);
    let sibling = clone_sibling(&kernel, &leader, 19_421);
    kernel.exit_thread(&sibling, None).expect("retire sibling");

    assert!(matches!(
        leader
            .task()
            .fork_barrier_participants(sibling.thread().key()),
        Err(TaskParticipantError::UnknownThread { .. })
    ));
}
```

The test names would fail if an implementation returned an empty set for an
unknown owner or reused one generic witness type.

- [ ] **Step 3: Add failing non-final-exit tests**

Add one test proving the leader's exit witness has a survivor after a sibling
clone, and one proving the sole leader's witness does not permit non-final exit:

```rust
assert!(task.thread_exit_participants(leader_key)?.permits_nonfinal_exit());
assert!(!sole_task.thread_exit_participants(sole_key)?.permits_nonfinal_exit());
```

Use `contains_survivor` to prove the survivor is the exact sibling identity.

- [ ] **Step 4: Add a failing dynamic crash-roster test**

In `kernel/crash_capture.rs`, create a quorum over a two-thread task, retire the
sibling between two polls, and assert the second poll no longer waits for the
retired identity. The expected result is derived from literal thread keys and
votes; do not calculate it with `Task::threads()`.

- [ ] **Step 5: Verify RED**

Run:

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime task_mints_distinct_fork_and_crash_sibling_witnesses --lib
```

Expected: compilation fails with missing `fork_barrier_participants`,
`crash_barrier_participants`, and `TaskParticipantError` symbols.

- [ ] **Step 6: Commit the RED contract**

```bash
git add crates/carrick-runtime/src/kernel/operations.rs crates/carrick-runtime/src/kernel/crash_capture.rs
git commit -m "test(runtime): require task-minted participant witnesses"
```

Do not fast-forward this RED checkpoint to `main`.

---

### Task 3: Task Witness Types and Non-Final Exit

**Files:**
- Modify: `crates/carrick-runtime/src/kernel/objects.rs:4300-4410`
- Modify: `crates/carrick-runtime/src/kernel/operations.rs:2760-2810`
- Modify: `crates/carrick-runtime/src/kernel/mod.rs:70-90`

**Interfaces:**
- Consumes: Task 2 RED tests.
- Produces: `TaskParticipantError`, `ForkBarrierParticipants`,
  `CrashBarrierParticipants`, `ThreadExitParticipants`,
  `CrashCaptureParticipants`, `CoreNoteParticipants`, and their exact `Task`
  minting methods.

- [ ] **Step 1: Add the opaque purpose-specific types**

Use `BTreeSet<ThreadKey>` for the three identity decisions and
`BTreeMap<ThreadKey, ThreadRef>` for crash iteration. Keep fields private. Add
only the semantic methods named in the spec:

```rust
#[derive(Debug)]
pub(crate) struct ForkBarrierParticipants {
    siblings: BTreeSet<ThreadKey>,
}

impl ForkBarrierParticipants {
    pub(crate) fn requires_quiesce(&self) -> bool {
        self.siblings.iter().next().is_some()
    }

    pub(crate) fn contains_sibling(&self, key: ThreadKey) -> bool {
        self.siblings.contains(&key)
    }
}
```

Implement separate concrete structs for crash and exit; do not introduce a
generic wrapper, trait, macro, or type alias joining them. `CoreNoteParticipants`
converts its private identity set with:

```rust
pub(crate) fn required_note_count_for_probe(&self) -> u64 {
    u64::try_from(self.members.iter().count()).unwrap_or(u64::MAX)
}
```

This is the only numeric Task-population projection.

- [ ] **Step 2: Implement one-lock Task minting**

Each owner-authenticated method locks `self.threads` once, verifies the exact
`ThreadKey` stored under the owner's Linux TID, and returns
`TaskParticipantError::UnknownThread` on mismatch. Construct sibling sets by
filtering the owner/departing key. `crash_capture_participants` and
`core_note_participants` require no owner and snapshot all current exact keys.

- [ ] **Step 3: Replace non-final thread-exit scalar authority**

In `Kernel::exit_thread`, mint `thread_exit_participants(context.thread.key())`
while the registry write authority is held. Map `UnknownThread` to the existing
`KernelOperationError::UnknownThread(tid)`. Return
`LastThreadRequiresTaskExit` only when
`permits_nonfinal_exit()` is false. Delete the production
`Task::live_thread_count` method; test-only cardinality assertions must use a
`#[cfg(test)] thread_count_for_test()` helper so the source gate can distinguish
them from production authority.

- [ ] **Step 4: Export only required visibility**

Re-export `TaskParticipantError` where runtime consumers need it. Keep witness
fields and test-only cardinality private; do not add `len`, `is_empty`,
`IntoIterator`, `Deref`, or numeric comparison APIs.

- [ ] **Step 5: Verify GREEN for Task contracts and exit behavior**

Run:

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime task_mints_distinct_fork_and_crash_sibling_witnesses --lib
RUSTC_WRAPPER= cargo test -p carrick-runtime task_participant_witness_rejects_a_stale_exact_owner --lib
RUSTC_WRAPPER= cargo test -p carrick-runtime thread_exit --lib
python3 scripts/migrate/check-task-participant-witnesses.py --path crates/carrick-runtime/src/kernel/objects.rs
python3 scripts/migrate/check-task-participant-witnesses.py --path crates/carrick-runtime/src/kernel/operations.rs
```

Expected: every command exits zero. The checker accepts only the explicitly
test-only count helper.

- [ ] **Step 6: Commit the Task authority**

```bash
git add crates/carrick-runtime/src/kernel/objects.rs crates/carrick-runtime/src/kernel/operations.rs crates/carrick-runtime/src/kernel/mod.rs
git commit -m "refactor(runtime): mint purpose-specific task participants"
```

Request independent review of this Codex-owned architecture before delegating
consumer work. Repair findings locally and rerun Step 5.

---

### Task 4: Identity Executor Census and Generation-Stamped Crash RAII

**Files:**
- Modify: `crates/carrick-runtime/src/kernel/guest_execution.rs`
- Modify: `crates/carrick-runtime/src/kernel/objects.rs:5100-5130,6285-6320`
- Modify: `crates/carrick-runtime/src/kernel/mod.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs:2450-2490` and exact enrollment call sites only
- Modify: `scripts/migrate/runtime-aborts/runtime.json` only if the exact abort census changes

**Interfaces:**
- Consumes: existing census-before-registry helper and `ThreadKey` identity.
- Produces: identity-set `GuestExecutorCensus`, typed admission errors,
  `CrashSafePointParticipationId`, and non-cloneable
  `CrashSafePointParticipation`.

- [ ] **Step 1: Add RED census behavior tests**

Before changing production storage, replace scalar assertions in
`kernel/guest_execution.rs` tests with behaviors that require identity:

```rust
#[test]
fn duplicate_exact_thread_admission_is_rejected() {
    let (_kernel, context) = bootstrap_thread(19_500);
    let census = Arc::new(GuestExecutorCensus::default());
    let _first = census
        .enter(Some(context.thread()))
        .expect("first exact participant");
    assert!(matches!(
        census.enter(Some(context.thread())),
        Err(GuestExecutorCensusError::DuplicateThread { .. })
    ));
}

#[test]
fn dropping_one_exact_participant_preserves_the_other() {
    let census = Arc::new(GuestExecutorCensus::default());
    let first = census.enter(None).expect("first token");
    let second = census.enter(None).expect("second token");
    assert!(census.has_peer_executor());
    drop(second);
    assert!(!census.has_peer_executor());
    drop(first);
    assert_eq!(census.participant_count_for_probe(), 0);
}
```

Add a generation test in the `objects.rs` test module that mints guard A,
revokes A through the private retirement cleanup, mints guard B, and invokes the
private release primitive with A's id. Assert the release result is
`Superseded`, B remains active, then `mem::forget(A)` and drop B normally. The
production mutation that would fail this test is an unqualified boolean
`store(false)` in A's release path. `CrashSafePointParticipation::drop` maps a
`Superseded` result to the classified carrier abort; the test exercises the
real release primitive without terminating the harness.

- [ ] **Step 2: Verify RED**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime duplicate_exact_thread_admission_is_rejected --lib
```

Expected: compilation fails because `enter` does not return `Result` and the
typed error/guard IDs do not exist.

- [ ] **Step 3: Replace `AtomicUsize` with exact identities**

Implement `GuestExecutorCensusState` as
`Mutex<BTreeSet<GuestExecutorIdentity>>` plus a monotonic anonymous-token
allocator. Exact thread entry inserts `GuestExecutorIdentity::Thread(key)` and
returns `DuplicateThread` if already present. Anonymous entry allocates a
non-zero never-reused id and returns `AnonymousIdentityExhausted` at wrap.

Thread entry is transactional across the census set and crash guard. If crash
guard minting fails after identity insertion, remove the exact inserted identity
before returning the typed error. A test must assert both the error and a zero
probe count after that failure; no half-membership may survive.

`has_peer_executor()` uses `participants.iter().nth(1).is_some()`. Delete
`live()`. `participant_count_for_probe()` performs a saturating `i32`
conversion and is never used for control flow.

- [ ] **Step 4: Implement generation-stamped crash participation**

Replace the `AtomicBool` with an active-generation `AtomicU64` and monotonic
next-generation allocator. `enter_crash_safe_point_participation` mints a fresh
non-zero id only from active zero. The guard's drop uses compare-exchange:

- exact id -> zero: success;
- zero: already revoked by retirement, success;
- different non-zero id: `std::process::abort()` without clearing it.

`Task::retire_thread` calls a private revoke operation that swaps the active id
to zero. Classify any new raw abort in the exact ledger with its carrier-fault
rationale; do not increase typed-error debt.

- [ ] **Step 5: Preserve census-before-registry production ordering**

Change `enter_guest_executor_then_register` to return a typed `Result`. It must
complete census/crash admission before invoking the `register` closure. Map
admission failure into the existing `RuntimeError::Configuration` boundary.
Update only the helper and its exact call sites here; fork/crash population
consumer migration remains delegated.

- [ ] **Step 6: Verify GREEN and ordering**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime guest_execution --lib
RUSTC_WRAPPER= cargo test -p carrick-runtime census_admission_precedes_registry_publication --lib
RUSTC_WRAPPER= cargo test -p carrick-runtime crash_quorum --lib
python3 scripts/migrate/check-runtime-aborts.py --check
python3 scripts/migrate/check-task-participant-witnesses.py --path crates/carrick-runtime/src/kernel/guest_execution.rs
```

Expected: all exit zero; duplicate identity is typed, unwind removes the exact
identity, retirement revocation cannot clear a successor, and abort debt remains
unchanged.

- [ ] **Step 7: Commit the identity census**

```bash
git add crates/carrick-runtime/src/kernel/guest_execution.rs crates/carrick-runtime/src/kernel/objects.rs crates/carrick-runtime/src/kernel/mod.rs crates/carrick-runtime/src/vcpu_loop/mod.rs scripts/migrate/runtime-aborts/runtime.json
git commit -m "refactor(runtime): identify guest executor participation"
```

Request independent review of generation/revocation and admission ordering.
Repair findings locally before delegation.

---

### Task 5: Dynamic Crash Roster and Codex-Owned Source Closure

**Files:**
- Modify: `crates/carrick-runtime/src/kernel/crash_capture.rs`
- Modify: `crates/carrick-runtime/src/kernel/operations.rs` tests if names changed
- Modify: `docs/identity-and-scope-domains.md` only for the already-existing lifecycle evidence correction

**Interfaces:**
- Consumes: `Task::crash_capture_participants`, Task 2 dynamic roster RED test,
  and existing `CrashQuorum` vote semantics.
- Produces: dynamic purpose-specific crash polling with no generic `Task::threads()` dependency.

- [ ] **Step 1: Migrate `CrashQuorum::poll`**

Mint `self.task.crash_capture_participants()` on every call and iterate only
`into_threads()`. Preserve the current order of interpretation:

1. published vote;
2. withdrawn vote;
3. missing live crash participant -> `Waiting(exact_tid)`;
4. nonparticipant parked registers -> collected fallback;
5. otherwise omitted.

Do not snapshot the roster in `CrashQuorum::open`.

- [ ] **Step 2: Correct the lifecycle receipt**

Update `identity-and-scope-domains.md` to state that the explicit run-state
requirement is satisfied by the pre-existing scheduler-owned
`ThreadExecutionState`; this milestone does not add a second state. Retain the
population work as open until Tasks 6-8 are complete.

- [ ] **Step 3: Verify dynamic behavior and source closure**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime crash_quorum --lib
RUSTC_WRAPPER= cargo test -p carrick-runtime crash_capture --lib
python3 scripts/migrate/check-task-participant-witnesses.py --path crates/carrick-runtime/src/kernel/crash_capture.rs
git diff --check
```

Expected: all commands exit zero and retirement between polls removes the exact
owed identity.

- [ ] **Step 4: Commit the dynamic roster**

```bash
git add crates/carrick-runtime/src/kernel/crash_capture.rs docs/identity-and-scope-domains.md
git commit -m "refactor(runtime): type crash capture participants"
```

At this commit the Codex-owned interfaces are frozen for worker consumption.

---

### Task 6: Antigravity Fork-Barrier Consumer Migration

**Files:**
- Worker may modify: `crates/carrick-runtime/src/vcpu_loop/quiesce.rs`
- Worker may modify: `crates/carrick-runtime/src/vcpu_loop/continuation.rs` only for existing source-contract assertions naming the retired expression
- Worker must not modify any other file.

**Interfaces:**
- Consumes: `Task::fork_barrier_participants(ThreadKey) -> Result<ForkBarrierParticipants, TaskParticipantError>` and `requires_quiesce()`.
- Produces: process-fork barrier selection with no raw durable-membership arithmetic.

- [ ] **Step 1: Preflight Antigravity once for this execution session**

```bash
agy -p "Reply with exactly: OK" --print-timeout 60s </dev/null
```

Expected: exactly `OK`. A sign-in URL or credential error stops delegation and
requires the user to run `agy` interactively; do not retry silently.

- [ ] **Step 2: Create and verify the isolated worker worktree**

```bash
git worktree add /Volumes/CaseSensitive/carrick/.worktrees/agy-task-participant-fork -b agy/task-participant-fork
git -C /Volumes/CaseSensitive/carrick/.worktrees/agy-task-participant-fork rev-parse HEAD
git rev-parse HEAD
```

Expected: both hashes are the exact Task 5 head and worker status is clean.

- [ ] **Step 3: Dispatch the bounded brief**

Use the installed `agy_worker.py`, schema
`schemas/work-contract.json`, `gemini-3.7-flash-high`, and a 20-minute timeout.
The brief must state:

- read `/Volumes/CaseSensitive/carrick/AGENTS.md` first;
- replace only the fork barrier's raw sibling arithmetic with the approved
  witness and typed error propagation;
- preserve durable membership semantics, barrier-before-drain order, and every
  wake/retry path;
- update only the retired source-contract assertion in `continuation.rs`;
- do not modify files outside the two-file fence; report any required interface
  change in `questions_for_director`;
- writes use cwd-relative paths, while search/read tools use absolute paths;
- run:

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime process_fork --lib
python3 scripts/migrate/check-task-participant-witnesses.py --path crates/carrick-runtime/src/vcpu_loop/quiesce.rs
RUSTC_WRAPPER= cargo fmt --all -- --check
```

- do not report `tests_passing: true` unless all commands exit zero.

- [ ] **Step 4: Collect and apply the two review gates**

Mechanical gate requires structured status `done`, nonempty `tests_run`,
`tests_passing: true`, and empty blockers. Then inspect:

```bash
git -C /Volumes/CaseSensitive/carrick/.worktrees/agy-task-participant-fork diff HEAD^..HEAD
```

Re-run the three exact verification commands yourself in the worker worktree.
Review owner authentication, error lowering, and barrier ordering against the
spec—not the worker prose.

- [ ] **Step 5: Send confirmed findings back to the same conversation**

Use `agy_worker.py followup --name task-participant-fork --prompt-file ...`.
State failure scenarios and required outcomes, not patches. Repeat review and
verification for at most three rounds. Stop early on the same blocker twice.

- [ ] **Step 6: Integrate the reviewed worker commit**

Cherry-pick the exact reviewed worker commit into
`codex/fd-description-seam`, rerun the three gates there, and record the worker
name, conversation id, commit, rounds, and results in the ignored SDD ledger.

---

### Task 7: Antigravity Crash/Core/Probe Consumer Migration

**Files:**
- Worker may modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs`
- Worker must not modify any other file.

**Interfaces:**
- Consumes: `CrashBarrierParticipants`, `CoreNoteParticipants`, identity census
  entry/result, and `participant_count_for_probe`.
- Produces: crash barrier, core-note diagnostics, and page-table probe migration
  with unchanged semantics and probe ABI.

- [ ] **Step 1: Create and verify a second isolated worktree from the post-Task-6 canonical head**

```bash
git worktree add /Volumes/CaseSensitive/carrick/.worktrees/agy-task-participant-crash -b agy/task-participant-crash
git -C /Volumes/CaseSensitive/carrick/.worktrees/agy-task-participant-crash rev-parse HEAD
git rev-parse HEAD
```

Expected: identical hashes and clean worker status.

- [ ] **Step 2: Dispatch the bounded brief**

Use `agy_worker.py`, the work-contract schema, `gemini-3.7-flash-high`, and a
20-minute timeout. Require the worker to:

- read `AGENTS.md`;
- replace crash `threads().len() > 1` with the exact fatal-owner
  `CrashBarrierParticipants` witness;
- replace core required-thread cardinality with
  `CoreNoteParticipants::required_note_count_for_probe` only at the probe
  boundary;
- replace every retired census `live()` use with
  `participant_count_for_probe` only where the existing four-position probe ABI
  requires a number;
- preserve crash admission, generation advertisement, barrier, lease drain,
  quorum, snapshot, cleanup, and lifecycle-probe ordering byte-for-byte except
  for typed population acquisition/error lowering;
- edit no file outside `vcpu_loop/mod.rs` and report interface gaps rather than
  inventing APIs;
- use cwd-relative writes and absolute search paths;
- run:

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime core_publication --lib
RUSTC_WRAPPER= cargo test -p carrick-runtime process_fork --lib
RUSTC_WRAPPER= cargo test -p carrick-runtime waiting_vcpu_tid --lib
python3 scripts/migrate/check-task-participant-witnesses.py --path crates/carrick-runtime/src/vcpu_loop/mod.rs
RUSTC_WRAPPER= cargo fmt --all -- --check
```

- report `tests_passing: true` only after all exit zero.

- [ ] **Step 3: Review, verify, and redispatch findings**

Apply the same two gates as Task 6. Inspect the actual diff for exact fatal
owner identity, error handling before any barrier publication, preservation of
the four probe arguments, and no numeric control decision. Send each confirmed
finding back to the same conversation for at most three rounds, rerunning all
five commands after every repair.

- [ ] **Step 4: Integrate the reviewed worker commit**

Cherry-pick the exact reviewed commit to canonical and record worker identity,
conversation id, rounds, commit, and Codex verification in the SDD ledger.

---

### Task 8: Source-Gate Closure, Full Verification, Review, and Main Fast-Forward

**Files:**
- Modify: `docs/identity-and-scope-domains.md`
- Modify: `docs/runtime-abstraction-audit-2026-08-27.md`
- Modify: `.superpowers/sdd/2026-08-28-task-participant-witnesses/progress.md` (ignored controller ledger)
- Remove worktrees after integration: `agy-task-participant-fork`, `agy-task-participant-crash`

**Interfaces:**
- Consumes: Tasks 1-7 reviewed implementation and receipts.
- Produces: complete population/lifecycle audit receipt and exact reviewed milestone on `main`.

- [ ] **Step 1: Run the full source closure**

```bash
python3 scripts/migrate/check-task-participant-witnesses.py --self-test
python3 scripts/migrate/check-task-participant-witnesses.py --check
rg -n "threads\(\)\.len\(\)|live_thread_count\(|GuestExecutorCensus::live|census\.live\(\)" crates/carrick-runtime/src
```

Expected: both checker commands exit zero. Any `rg` match is test-only or an
unrelated collection and must be inspected individually; no production
authority match remains.

- [ ] **Step 2: Run focused gates**

```bash
RUSTC_WRAPPER= just fmt-check
RUSTC_WRAPPER= cargo test -p carrick-runtime guest_execution --lib
RUSTC_WRAPPER= cargo test -p carrick-runtime task_participant --lib
RUSTC_WRAPPER= cargo test -p carrick-runtime crash_quorum --lib
RUSTC_WRAPPER= cargo test -p carrick-runtime process_fork --lib
RUSTC_WRAPPER= cargo test -p carrick-runtime core_publication --lib
RUSTC_WRAPPER= cargo test -p carrick-thread fork_quiesce --lib
RUSTC_WRAPPER= cargo test -p carrick-observability --lib
```

Expected: every command exits zero.

- [ ] **Step 3: Run repository-wide gates serially**

```bash
RUSTC_WRAPPER= just clippy
RUSTC_WRAPPER= just doc
RUSTC_WRAPPER= just lint-domains
RUST_TEST_THREADS=1 RUSTC_WRAPPER= just ci
```

`clippy` and `doc` must exit zero. `lint-domains` and `just ci` may stop nonzero
only at the documented compiler host-authority positional inventory check, and
only when its machine output says `changed=[]`. Do not rebaseline position-only
drift. Any earlier/later failure or nonempty `changed` set is red.

If that known stop prevents later recipes, run each explicitly and require exit
zero:

```bash
RUSTC_WRAPPER= just deny
RUSTC_WRAPPER= just check-matrix
RUSTC_WRAPPER= just check --workspace
RUSTC_WRAPPER= just doc
RUSTC_WRAPPER= just test
RUSTC_WRAPPER= just test-integration
```

Run `just test-integration` outside the filesystem/network sandbox if sandbox
socket binds or set-id preservation return `EPERM`; record both the restricted
failure and unrestricted authoritative pass.

- [ ] **Step 4: Write the exact completion receipt**

Update both controlling audit documents with:

- exact source head and gate results;
- deletion of raw Task population arithmetic and scalar executor census;
- named witness types and generation-stamped crash RAII;
- confirmation that `ThreadExecutionState` was reused rather than duplicated;
- exact Antigravity worker conversation/commit/review rounds;
- abort ledger totals and any `changed=[]` host-authority receipt; and
- explicit statement that MM authority and structural lock order remain open.

Do not claim the full runtime audit complete at this milestone.

- [ ] **Step 5: Obtain two independent reviews and repair findings**

Reviewer A covers Task witness selection, exact owner authentication,
thread-exit behavior, and fork migration. Reviewer B covers executor identity,
generation-stamped crash RAII, crash/core migration, source gate, and receipts.
Require concrete failure scenarios. Confirm findings against current source;
send Antigravity-owned consumer findings to the original worker conversation
and repair Codex-owned findings locally. Re-run affected focused gates after
each repair.

- [ ] **Step 6: Commit the reviewed receipt and verify branch state**

```bash
git add docs/identity-and-scope-domains.md docs/runtime-abstraction-audit-2026-08-27.md
git commit -m "docs(runtime): close typed participant populations"
git status --short
git diff --check main...HEAD
git log --oneline --decorate -16
```

Expected: clean tracked status, no whitespace errors, and a narrow reviewed
series from Task 1 through Task 8.

- [ ] **Step 7: Fast-forward the independently reviewed GREEN milestone to `main`**

From `/Volumes/CaseSensitive/carrick`:

```bash
git status --short --branch
git merge --ff-only codex/fd-description-seam
git rev-parse main
git rev-parse codex/fd-description-seam
git rev-list --left-right --count main...codex/fd-description-seam
```

Expected: clean main worktree, identical commit hashes, and `0 0`. Do not push.

- [ ] **Step 8: Reap Antigravity and remove integrated worktrees**

Use the exact run-scoped `AGY_RUN_ID` with `agy_worker.py reap`; never use
`pkill -f agy`. Remove only the two named clean, fully integrated worktrees and
delete their local worker branches after confirming their commits are ancestors
of `main`.
