# Scheduler Preemption Conformance and Cost Acceptance Campaign (2026-09-19)

## 1. Executive Summary

Syscall-free, CPU-bound guest tasks previously monopolized Carrick carrier vCPUs because Carrick lacked preemptive time-slice tracking and non-blocking quantum revocation for running tasks. Under high CPU contention or infinite compute loops without syscall traps, runnable threads would starve indefinitely.

This campaign verifies the implementation of the **Pluggable Scheduler Preemption Design** (`docs/superpowers/specs/2026-09-19-pluggable-scheduler-preemption-design.md`), establishing:
1. Pluggable preemption policies via `PreemptionAction` and dynamic runtime budget negotiation.
2. Dynamic demand tracking with active slot accounting and non-blocking quantum expiration.
3. Asynchronous preemption delivery through `ExecutorKick` without host thread disruption.
4. Exact composition with host-wait handoff, cancellation, and stdio backpressure.
5. Three new formal conformance contracts verified across VM-free, embed structural, and embed timing layers.
6. End-to-end guest verification under signed Hypervisor.framework execution on Apple Silicon (AArch64).

---

## 2. Registered Conformance Contracts & Structural Budgets

Three new formal contracts have been registered in `conformance-contracts/contracts/` and checked against all surfaces via `check-contracts`:

| Contract ID | Title | Key Structural Budget | Primary Semantic Assertions |
| --- | --- | --- | --- |
| `kernel.scheduler.runnable-progress` | Runnable scheduler preemption progress | `kernel_dispatches` (affine: base 0, per-unit 1) | `all_tasks_dispatched`, `exact_affinity` |
| `kernel.scheduler.preemption-lifecycle` | Preemption lifecycle & stale-request protection | `vcpu_migrations` (exact: 0) | `stale_request_rejected`, `control_reasons_survive`, `slot_ownership_conserved` |
| `kernel.scheduler.preemption-cost` | Preemption cost & scalability | `kernel_redispatches` (upper bound: 0) | `uncontended_zero_fairness`, `deadlines_bounded_by_slots`, `zero_idle_work` |

All contract definitions specify a maximum runtime ratio of 2.0x against the Docker baseline with at least 20 samples.

---

## 3. Real Guest Verification (AArch64 Syscall-Free Compute Loop)

To prove real guest progress without synthetic or mock syscall traps, a pure AArch64 Linux compute fixture was constructed:
- **Source:** `fixtures/linux-aarch64-hello/src/scheduler_preemption.rs`
- **Target:** `aarch64-unknown-linux-musl` static ELF (2,336 bytes, zero dynamic dependencies).
- **Workload:** The leader process creates a shared memory region, spawns 4 worker threads via `SYS_CLONE` with private stacks, and each worker executes a 20,000,000-iteration compute loop using ARMv8 atomics (`ldaxr`/`stlxr`) without issuing any Linux syscalls.
- **Verification:** The controller awaits completion of all 4 workers and asserts all iterations completed before writing `"preemption ok"` to stdout and exiting 0.

### Signed Execution Proof (`just test-embed scheduler_preemption`)

Under Apple Silicon signed Hypervisor.framework execution, all 7 tests in `carrick-embed/tests/scheduler_preemption.rs` passed cleanly:

```text
running 7 tests
test scheduler_preemption_cost_contract ... ok
test scheduler_preemption_cost_structural_and_timing_receipts_are_distinct ... ok
test scheduler_preemption_guest_compute_progress ... ok
test scheduler_preemption_lifecycle_contract ... ok
test scheduler_preemption_lifecycle_structural_and_timing_receipts_are_distinct ... ok
test scheduler_preemption_progress_contract ... ok
test scheduler_preemption_progress_structural_and_timing_receipts_are_distinct ... ok

test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.44s
test-signed: negative control on target/release/deps/entitlement_negative-...: ok
remaining carrick procs = 0
test-signed: OK (carrick-embed: 1 invoked signed executable(s) passed, 13 signed, negative control passed)
```

---

## 4. Conformance & Verification Results Summary

### VM-Free Conformance Tests (`carrick-kernel-example/tests/contracts.rs`)
- `scheduler_progress_contract_is_semantically_exact_and_linear`: **PASSED**
- `scheduler_lifecycle_contract_is_semantically_exact_and_constant`: **PASSED**
- `scheduler_cost_contract_is_semantically_exact_and_constant`: **PASSED**
- All 17 workspace contract tests: **PASSED (0.09s)**

### Kernel Semantics Suite (`just test-kernel`)
- All 79 kernel semantics tests: **PASSED (0.07s)**
- All 8 socket close tests: **PASSED (0.01s)**
- All 22 socket receive tests: **PASSED (0.01s)**
- Stdio host-wait contention & backpressure tests: **PASSED**
- Unicode path tests: **PASSED**

### Host Integration & Harness Suites (`just test` and `just test-integration`)
- `just test`: **492 passed; 0 failed; 3 ignored (7.77s)**
- `just test-integration`: **84 passed; 0 failed (19.8s)**
- Engine, image, and conformance-next shard tests: **PASSED**

### Static Quality Gates
- `just fmt-check`: **PASSED (clean)**
- `just clippy`: **PASSED (0 warnings across workspace and all targets)**
- `just lint-domains`: **PASSED (9 contracts, 36 surfaces, census verified)**
- `just check-matrix`: **PASSED (docs/support-matrix.md in exact sync)**
- `just doc`: **PASSED (0 warnings with RUSTDOCFLAGS="-D warnings")**
