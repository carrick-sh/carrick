# HVPatch Adaptive Syscall Portal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Service eligible scalar HVPatch syscalls through an adaptive typed mailbox portal while preserving Carrick kernel, scheduler, signal, observer, and generation authority.

**Architecture:** The existing `Aarch64SyscallMailbox` gains named portal state and session fields. An executor-local runtime helper validates an exact task/MM/mailbox/quantum identity and runs the ordinary dispatcher while EL1 waits; it returns scalar results directly or retains a complex outcome for the vCPU owner. The helper parks outside bounded syscall-dense sessions, and every uncertain condition takes the current HVC path.

**Tech Stack:** Rust 2024, Carrick kernel graph and work-meter contracts, AArch64 instruction emitters, Hypervisor.framework/HVF, signed `carrick-embed` tests, Docker differential oracle.

**Spec:** `docs/superpowers/specs/2026-09-20-hvpatch-syscall-portal-design.md`

## Global Constraints

- Use `Aarch64SyscallMailbox`, named `offset_of!` constants, and typed protocol enums; do not decode raw byte offsets.
- The first production allowlist is exactly regular-file `lseek` and `inotify_rm_watch`.
- `sched_yield`, pointer-bearing calls, blocking outcomes, MM mutation, task migration, signals, and active incompatible observers take HVC.
- The helper never invokes an HVF vCPU API and never owns task or MM rebinding.
- Portal selection defaults off until the signed structural and timing gates pass; `CARRICK_HVPATCH_SYSCALL_PORTAL=adaptive` selects the experimental path.
- Missing metrics, stale generations, unknown states, dropped events, and incomplete cleanup fail closed.
- Build guests with `just build` or `just test-embed`; never run an unsigned HVF executable.
- Never run Carrick and Docker concurrently.

## Review Focus

- A signal published after the helper response but before EL1 `eret` must force the host boundary before guest execution resumes; Task 4 adds this race test.
- A task migrated to a reused mailbox slot must reject the prior task's request and response generations; Tasks 2 and 3 add stale-session tests.
- An eligible syscall that unexpectedly returns a blocking or scheduler outcome must execute once and transfer that exact outcome to the vCPU owner; Task 3 adds a no-redispatch test.
- A compute-bound or idle guest must leave the helper parked and consume no sustained helper CPU; Tasks 3 and 5 add activity-window and process-CPU checks.
- An interceptor or observer requiring owner-thread behavior must disable portal admission without losing syscall entry/return evidence; Tasks 3 and 4 add policy and probe checks.

---

### Task 1: Portal work metrics and contract skeleton

**Files:**
- Modify: `crates/carrick-observability/src/work_meter.rs`
- Modify: `crates/carrick-observability/tests/work_meter.rs`
- Create: `conformance-contracts/contracts/hvpatch-syscall-portal.toml`
- Create: `conformance-contracts/claims/hvpatch-syscall-portal.toml`
- Modify: `conformance-contracts/surfaces.toml`
- Modify: `conformance-contracts/inventory.json`

**Interfaces:**
- Produces: `WorkMetric::{HvfSyscallExits, PortalRequests, PortalCompletions, PortalFallbacks, PortalStaleRejects}`.
- Produces: contract ID `hvpatch.syscall.portal` with scale points `1, 8, 32, 128` and unresolved signed/timing bindings until Tasks 4 and 5.

- [ ] **Step 1: Write the failing work-meter round-trip test**

Add a test that inserts and serializes each new metric, deserializes the snapshot, and asserts every value remains distinct. Update `WorkMetric::COUNT` only after the test fails for missing variants.

```rust
for (index, metric) in [
    WorkMetric::HvfSyscallExits,
    WorkMetric::PortalRequests,
    WorkMetric::PortalCompletions,
    WorkMetric::PortalFallbacks,
    WorkMetric::PortalStaleRejects,
]
.into_iter()
.enumerate()
{
    scope.add(metric, index as u64 + 1).unwrap();
}
```

- [ ] **Step 2: Run the test red**

Run: `RUSTC_WRAPPER= cargo test -p carrick-observability --test work_meter portal_metrics_round_trip --exact`

Expected: compile failure naming the missing metric variants.

- [ ] **Step 3: Add the metric variants and exact producers' documentation**

Append the five variants to `WorkMetric`, update `COUNT` and `ALL`, and document that `HvfSyscallExits` counts syscall HVC boundaries only, while the portal counters count accepted requests, direct completions, forced host boundaries, and stale rejections.

- [ ] **Step 4: Add the contract and claim**

Set the VM-free structural budgets to:

```toml
[[structural_budgets]]
kind = "affine"
metric = "portal_requests"
base = 0
per_unit = 1
layers = ["vm-free"]
rationale = "Each admitted fixture operation publishes exactly one typed request."

[[structural_budgets]]
kind = "affine"
metric = "portal_stale_rejects"
base = 0
per_unit = 0
rationale = "A current session must never accept stale state."
```

Record `vm_free` as unresolved until Task 3, `embed_structural` until Task 4, and `embed_timing` until Task 5. Bind the claim to `syscall:lseek`, `syscall:inotify_rm_watch`, and `vmm:hvf` without claiming transport parity for KVM, bhyve, or NVMM.

- [ ] **Step 5: Regenerate inventory and run registry tests**

Run:

```sh
RUSTC_WRAPPER= cargo run -p carrick-conformance-contract --bin generate-inventory
RUSTC_WRAPPER= cargo test -p carrick-conformance-contract
RUSTC_WRAPPER= cargo run -p carrick-conformance-contract --bin check-contracts -- --root .
```

Expected: the registry accepts explicit unresolved bindings and inventory records the two syscall surfaces.

- [ ] **Step 6: Commit**

```sh
git add crates/carrick-observability conformance-contracts
git commit -m "test(hvpatch): define syscall portal contract"
```

### Task 2: Typed mailbox portal protocol and EL1 fallback

**Files:**
- Modify: `crates/carrick-mem/src/memory.rs`
- Modify: `crates/carrick-aarch64/src/mailbox.rs`
- Modify: `crates/carrick-vmm-hvf/src/syscall_mailbox.rs`
- Test: inline tests in those modules

**Interfaces:**
- Produces: `PortalState::{Disabled, Armed, RequestReady, ResponseReady, HostBoundary, Cancelling}` encoded in named mailbox fields.
- Produces: `PortalSessionWire { executor_generation, task_serial, mm_generation, quantum_epoch }` stored within the existing 256-byte mailbox.
- Produces: `MailboxBinding::{arm_portal, cancel_portal, portal_snapshot, publish_portal_response}`; all require a live binding generation.

- [ ] **Step 1: Write red layout and transition tests**

Add compile-time offset assertions and runtime tests that require a 256-byte,
64-byte-aligned mailbox, validate only these transitions, and reject every
unknown state:

```text
Disabled -> Armed -> RequestReady -> ResponseReady -> Armed
Armed|RequestReady|ResponseReady -> Cancelling -> Disabled
RequestReady -> HostBoundary -> Armed
```

Add stale tests for mailbox generation, executor generation, task serial, MM generation, quantum epoch, and non-increasing sequence.

- [ ] **Step 2: Run the protocol tests red**

Run: `RUSTC_WRAPPER= cargo test -p carrick-aarch64 mailbox::tests -- --nocapture`

Expected: compile failure naming the new wire types and binding methods.

- [ ] **Step 3: Extend the typed mailbox without changing its size**

Replace enough of `reserved: [u8; 24]` with named `u32`/`u64` portal fields, derive every instruction offset with `offset_of!`, and keep existing clock fields and protocol values unchanged. Reject any layout that exceeds 256 bytes at compile time.

- [ ] **Step 4: Add a generated eligibility predicate**

Add:

```rust
pub const fn portal_scalar_eligible(native_nr: u64) -> bool {
    matches!(native_nr, 62 | 28) // aarch64 lseek, inotify_rm_watch
}
```

Tie the numeric values to `carrick-abi` in a higher-layer unit test so table drift fails. Do not admit `write`, `inotify_add_watch`, or `sched_yield`.

- [ ] **Step 5: Emit the EL1 portal branch with HVC fallback**

In `el1_vectors_bytes_mailbox_inner`, preserve x0-x5, x8, x16, and x17 exactly as today. When the syscall is eligible and the typed state is `Armed`, publish `RequestReady`, poll for `ResponseReady` or `HostBoundary`, re-check `CLOCK_FORCE_HOST_BOUNDARY`, and return only a normal scalar response. Every other state branches to the existing HVC instruction. Use existing encoder helpers plus new named helpers; do not place literal mailbox offsets in emitted code.

- [ ] **Step 6: Run protocol, vector, and red-control tests**

Run:

```sh
RUSTC_WRAPPER= cargo test -p carrick-mem mailbox
RUSTC_WRAPPER= cargo test -p carrick-aarch64 mailbox
RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf syscall_mailbox
```

The red control constructs `Disabled` state and asserts the vector still reaches the existing HVC opcode.

- [ ] **Step 7: Commit**

```sh
git add crates/carrick-mem crates/carrick-aarch64 crates/carrick-vmm-hvf/src/syscall_mailbox.rs
git commit -m "feat(hvpatch): define typed syscall portal protocol"
```

### Task 3: Adaptive runtime session and scalar dispatcher

**Files:**
- Create: `crates/carrick-runtime/src/vcpu_loop/portal.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/binding.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/executor.rs`
- Modify: `crates/carrick-hal/src/threaded.rs`
- Modify: `crates/carrick-vmm-hvf/src/trap/persistent_executor.rs`
- Test: `crates/carrick-runtime/src/vcpu_loop/executor/tests.rs`

**Interfaces:**
- Consumes: Task 2 mailbox states and `portal_scalar_eligible`.
- Produces: `PortalSessionIdentity`, `PortalPolicy`, `PortalEndpoint`, `PortalCompletion`, and `AdaptivePortalSession`.
- Produces: `ThreadedEngine::portal_endpoint() -> Option<PortalEndpoint>` with a default `None` for non-HVF engines.

- [ ] **Step 1: Write the red state-machine tests**

Create scripted tests for:

```rust
assert_eq!(session.state(), PortalRuntimeState::Parked);
session.arm(identity.clone()).unwrap();
assert_eq!(session.service(request(identity.clone())), PortalCompletion::Returned(7));
assert_eq!(session.service(request(stale_identity)), PortalCompletion::StaleRejected);
session.cancel(identity.quantum_epoch + 1).unwrap();
assert_eq!(session.state(), PortalRuntimeState::Parked);
```

Add tests that a blocking `DispatchOutcome`, `SchedulerYield`, signal debt,
active incompatible interceptor, and expired activity window each produce one
`HostBoundary`, preserve the produced outcome, and never dispatch twice.

- [ ] **Step 2: Run the runtime tests red**

Run: `RUSTC_WRAPPER= cargo test -p carrick-runtime portal -- --nocapture`

Expected: compile failure for the missing portal module and types.

- [ ] **Step 3: Implement policy and session identity**

Parse `CARRICK_HVPATCH_SYSCALL_PORTAL` as `off` or `adaptive`, defaulting to `off` and rejecting every other value. Define the identity from existing typed executor, task, MM, mailbox, and quantum generations; do not cast pointers or derive identity from host addresses.

- [ ] **Step 4: Implement the parked helper lifecycle**

Spawn one helper with each persistent HVF executor. It waits on a condition variable while parked, polls the mailbox only while armed, renews a named operation/time budget after each valid request, and returns to the condition variable on expiry or cancellation. `Drop`/executor retirement cancels, joins, and proves the helper idle before mailbox release.

- [ ] **Step 5: Dispatch only the scalar allowlist**

Construct the ordinary `PreparedSyscall` and retained kernel context from the validated request. Use an empty `LinearMemory` as a fail-closed guest-memory backend. Accept only `Returned` and `Errno` for direct response; move every other `DispatchOutcome` into the owner-consumed `PortalCompletion::HostBoundary` slot.

- [ ] **Step 6: Wire work metrics at their real events**

Increment `PortalRequests` after full request validation, `PortalCompletions` after response publication, `PortalFallbacks` when publishing `HostBoundary`, and `PortalStaleRejects` before rejecting an identity. Increment `HvfSyscallExits` at the existing HVC syscall decode, independent of portal state.

- [ ] **Step 7: Run tests including stale reuse and idle CPU behavior**

Run:

```sh
RUSTC_WRAPPER= cargo test -p carrick-runtime portal -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf persistent_executor -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-observability --test work_meter
```

Use a deterministic fake clock for the activity-window test; do not sleep in unit tests.

- [ ] **Step 8: Commit**

```sh
git add crates/carrick-runtime crates/carrick-hal crates/carrick-vmm-hvf crates/carrick-observability
git commit -m "feat(hvpatch): add adaptive scalar syscall portal"
```

### Task 4: Signal, kick, observer, and generation integration

**Files:**
- Modify: `crates/carrick-runtime/src/vcpu_loop/portal.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/binding.rs`
- Modify: `crates/carrick-vmm-hvf/src/vcpu_kick.rs`
- Modify: `crates/carrick-vmm-hvf/src/syscall_mailbox.rs`
- Modify: `crates/carrick-vmm-hvf/src/probes.rs`
- Test: `crates/carrick-runtime/src/vcpu_loop/executor/tests.rs`
- Test: `crates/carrick-vmm-hvf/src/trap/foreign_mm/tests.rs`

**Interfaces:**
- Consumes: `AdaptivePortalSession::cancel` and `PortalEndpoint`.
- Produces: exact cancellation handshake used before migration, MM change, task replacement, executor reclaim, and mailbox release.

- [ ] **Step 1: Add red race tests for each return-edge window**

Use the scripted engine to publish a signal in four positions: before request publication, while the helper dispatches, after response publication, and immediately before simulated `eret`. Each must return `HostBoundary`, service the signal once, and leave the session parked or safely re-armed for the same identity.

- [ ] **Step 2: Add red migration and mailbox-reuse tests**

Publish a request for task A, cancel and bind task B to the same mailbox slot, then deliver A's late response. Assert B observes no return value, `PortalStaleRejects == 1`, and the ordinary HVC path handles B's syscall.

- [ ] **Step 3: Integrate force-boundary checks and cancellation**

Reuse `CLOCK_FORCE_HOST_BOUNDARY` and the existing vCPU kick. Check it before EL1 publication, in the poll loop, after response acquire, and in the helper. Cancel and join the helper before every existing persistent-executor boundary audit that permits task/MM/mailbox replacement.

- [ ] **Step 4: Preserve observability semantics**

Emit the existing syscall entry and return USDT events from the helper with the same Linux name, number, args, retval, and errno. If an installed interceptor or observer cannot execute on the helper under its current contract, refuse admission before publication and count one fallback.

- [ ] **Step 5: Run the focused race and invariant suites**

Run:

```sh
RUSTC_WRAPPER= cargo test -p carrick-runtime portal_signal -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime portal_migration -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf mailbox -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf foreign_mm -- --nocapture
```

- [ ] **Step 6: Commit**

```sh
git add crates/carrick-runtime crates/carrick-vmm-hvf
git commit -m "fix(hvpatch): force portal boundaries for signals and migration"
```

### Task 5: Signed structural binding and red-first exit proof

**Files:**
- Create: `conformance-probes/src/bin/portal_scalar_scale.rs`
- Modify: `conformance-probes/probe-inventory.json`
- Create: `crates/carrick-embed/src/contracts/hvpatch_portal.rs`
- Modify: `crates/carrick-embed/src/contracts.rs`
- Modify: `crates/carrick-embed/src/lib.rs`
- Create: `crates/carrick-embed/tests/hvpatch_portal_contract.rs`
- Modify: `conformance-contracts/contracts/hvpatch-syscall-portal.toml`
- Modify: `conformance-contracts/surfaces.toml`

**Interfaces:**
- Consumes: Task 3 policy env and portal metrics.
- Produces: fail-closed signed observations at scales `1, 8, 32, 128`.

- [ ] **Step 1: Add the clean-room probe**

Write an Apache-2.0 OR MIT probe with two explicit modes. `lseek-scale N`
creates one private-rootfs file, executes one unmeasured arming `lseek`, then
executes exactly N additional `lseek(fd, 0, SEEK_SET)` calls. `rm-watch-semantic`
creates one inotify watch, removes it once, and proves the documented second
remove errno without making a scaling claim. Emit only mode, scale, completed
operations, offset/watch semantics, and completion status. Do not copy LTP
source or comments.

- [ ] **Step 2: Add the fail-closed signed parser**

Require a 64-hex `CARRICK_OBSERVATION_SOURCE`, digest-pinned image, present cross-built probe, exact transcript fields, zero exit-status error, clean shutdown, complete work metrics, and `CARRICK_HVPATCH_SYSCALL_PORTAL=adaptive` forwarded into the carrier.

- [ ] **Step 3: Capture the red control**

Build and sign with the policy `off`. Evaluate the portal contract and retain the first `ScalingViolation` where `HvfSyscallExits` grows one-for-one with scale. The control must pass semantic assertions; a broken probe is not red evidence.

- [ ] **Step 4: Capture the green portal observation**

Run the same source, image, scales, and signed test with policy `adaptive`.
Require `PortalRequests == scale`, `PortalCompletions == scale`,
`PortalStaleRejects == 0`, and an HVC exit budget of the one explicit arming
call plus fixed container scaffolding rather than one exit per scaled eligible
operation. Run `rm-watch-semantic` in the same signed executable as a separate
semantic assertion; do not mix its setup HVCs into the lseek scaling snapshot.

- [ ] **Step 5: Run registration and signed gates**

Run:

```sh
RUSTC_WRAPPER= cargo run -p carrick-conformance-contract --bin check-contracts -- --root .
RUSTC_WRAPPER= cargo test -p carrick-kernel-example --test contracts
CARRICK_TEST_SIGNED_FEATURES=conformance-metrics just test-embed hvpatch_portal_contract_budget --exact --nocapture
```

Preserve signer receipt, SHA-256, CDHash, LC_UUID, entitlement, DOF presence, source identity, image digest, observations, and scoped cleanup.

- [ ] **Step 6: Commit**

```sh
git add conformance-probes crates/carrick-embed conformance-contracts
git commit -m "test(hvpatch): bind adaptive portal contract"
```

### Task 6: Inotify09 impact, CPU budget, and promotion decision

**Files:**
- Modify only if evidence requires: `docs/superpowers/specs/2026-09-20-hvpatch-syscall-portal-design.md`
- Add measurement receipt under: `docs/perf-results/`

**Interfaces:**
- Consumes: one final signed artifact from Task 5.
- Produces: decision to retain experimental scalar coverage, advance to pointer-bearing MM lease work, or reject the portal on CPU/correctness evidence.

- [ ] **Step 1: Measure helper idle and active CPU**

Run the signed scalar probe in fixed `off, adaptive, adaptive, off` blocks. Record wall and aggregate process CPU. Add a compute-only guest interval after portal expiry and require no sustained helper CPU growth beyond the parked-thread measurement noise established by the off arms.

- [ ] **Step 2: Run the inotify decomposition**

Run `perf_inotify09_scale` with policy off and adaptive against the same signed artifact and digest-pinned image. Compare all five phases at scale 65,536; do not cite scale 1 warmup behavior as the result.

- [ ] **Step 3: Run exact LTP and inspect both streams**

Run:

```sh
CARRICK_RUN_ID=portal-inotify09 \
RUSTC_WRAPPER= cargo run -p carrick-conformance -- \
  --suite ltp-inotify09 --workers 1 --carrick-timeout-cap-s 0 \
  --require-cached-oracle --no-image-refresh \
  --jsonl target/conformance/portal-inotify09.jsonl
```

Inspect both raw `.out` and `.err` with `grep -a`, record the exact loop progress, timeout classification, Carrick/oracle milliseconds, and ratio.

- [ ] **Step 4: Decide from evidence**

Keep the scalar portal experimental if semantics and CPU pass but the workload remains above 2.0. Proceed to a separate authenticated current-MM read-lease spec for `write` and `inotify_add_watch` only if the measured HVC reduction predicts material remaining gain. Reject or redesign the portal if helper CPU, stale rejection, signal races, or fallback frequency violates its contract.

- [ ] **Step 5: Run the promotion ladder only after the focused ratio is acceptable**

Run on the unchanged signed artifact:

```sh
just conformance-probes
just --no-deps conformance smoke
just --no-deps conformance full
```

Any red rung blocks default enablement. Record every unrun rung as open rather than inferred green.

- [ ] **Step 6: Commit the evidence**

```sh
git add docs/perf-results docs/superpowers/specs/2026-09-20-hvpatch-syscall-portal-design.md
git commit -m "perf(hvpatch): qualify adaptive syscall portal"
```
