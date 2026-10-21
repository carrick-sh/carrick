# Typed Copyout Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make redispatch-safe owner-copyout waits signal-correct, prove the real production park/wake path, close focused wait/read coverage gaps, and make the debt ratchet monotone per file.

**Architecture:** Carry copyout redispatch as a typed resume kind into the zone continuation policy instead of classifying syscalls by number. Exercise the real owner portal and runtime continuation end to end, add kernel-level boundary cases, then strengthen the scanner's base comparison without expanding its syntactic scope.

**Tech Stack:** Rust, Carrick kernel/runtime continuation APIs, production EL1 owner portal test support, `carrick-xtask` source scanner.

**Spec:** `/tmp/review-739d.json` and `conformance-contracts/contracts/owner-refused-copyout.toml`

## Global Constraints

- Work only on top of `3298f2d95c`; add commits and do not rewrite history.
- No syscall-number allowlist for signal policy; select policy from a typed copyout resume kind.
- No retries, timeout widening, symptom serialization, pushes, PR edits, or GitHub comments.
- Keep pipe/socket publication, `prlimit64`, and socketpair partial-write concerns out of scope.
- Every commit uses Why/What/Verified and `Co-Authored-By: GPT-6.1 Sol <noreply@openai.com>`.

## Review Focus

- A caught non-`SA_RESTART` signal during `fstat` owner-copyout park must remain pending until the syscall completes.
- The same signal ordering must hold for `wait4`, while SIGKILL/group exit still terminate the park.
- Forgetting the sibling editor must prevent the production owner wait from becoming ready within a bounded test deadline.
- Stop/continue wait events, WNOHANG/NULL `waitid`, and suspended sockaddr length reads must survive refusal without consumption or EFAULT.
- A base comparison must reject an increase in any individual dispatch file even when total debt falls.

---

### Task 1: Typed non-interruptible copyout redispatch

**Files:**
- Modify: `crates/carrick-runtime/src/vcpu_loop/binding.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/zone.rs`
- Modify/Test: `crates/carrick-runtime/src/vcpu_loop/executor/residency.rs`
- Modify: `conformance-contracts/contracts/owner-refused-copyout.toml`

**Interfaces:**
- Produces a distinct owned resume kind for side-effect-free copyout redispatch.
- Maps that kind to a killable-only zone continuation while retaining ordinary signals for post-completion delivery.

- [ ] Add red tests for handled non-`SA_RESTART` signals during `fstat` and `wait4` owner-copyout parks plus fatal wake behavior.
- [ ] Run the focused tests on `3298f2d95c` and retain the EINTR failures.
- [ ] Add the typed resume/policy mapping and restore the exact contract property.
- [ ] Run focused runtime tests green and commit finding 1.

### Task 2: Real production editor release and continuation wake

**Files:**
- Modify/Test: `crates/carrick-runtime/src/vcpu_loop/mod.rs`
- Modify/Test as needed: `crates/carrick-runtime/src/vcpu_loop/executor/residency.rs`

**Interfaces:**
- Consumes Task 1's typed resume policy.
- Drives `owner_memory_park`, object wake, `consume_owner_zone`, and redispatch using the real editor readiness source.

- [ ] Replace the atomic refusal gate with production portal readiness and route through the zone continuation.
- [ ] Run the bounded `forget(editor)` negative control and retain its timeout failure.
- [ ] Run the `drop(editor)` production wake path green.
- [ ] Commit finding 2.

### Task 3: Wait-state and addrlen suspension coverage

**Files:**
- Modify/Test: `crates/carrick-kernel/src/dispatch/proc.rs`
- Modify/Test: `crates/carrick-kernel/src/dispatch/copyout_tests.rs`
- Modify/Test support: `crates/carrick-kernel/src/dispatch/copyout.rs`

**Interfaces:**
- Exercises existing prepared-copyout APIs without production behavior changes.

- [ ] Add tests for refused stop and continue reports surviving redispatch.
- [ ] Add `waitid(WNOHANG)` and NULL-infop refusal tests.
- [ ] Add refused addrlen-read tests that assert `from_read_error` maps to owner wait rather than EFAULT.
- [ ] Run focused kernel tests and commit finding 3.

### Task 4: Per-file debt monotonicity

**Files:**
- Modify/Test: `crates/carrick-xtask/src/copyout_debt.rs`

**Interfaces:**
- Compares current and base maps by dispatch path and rejects any positive file delta.
- Explicitly documents wrapper and function-pointer alias limitations.

- [ ] Add a red fixture where one file rises while aggregate debt falls.
- [ ] Implement per-file base comparison without expanding syntactic detection.
- [ ] Run scanner unit tests and the repository debt command; commit finding 4.

### Task 5: Stale comment cleanup

**Files:**
- Modify: `crates/carrick-kernel/src/dispatch/copyout.rs`

- [ ] Remove the reverted getdents64 example.
- [ ] Run formatting/check and commit finding 5.

### Task 6: Final verification

- [ ] Run kernel parallel and serial-host tests.
- [ ] Run focused runtime tests, with serial-host under `RUST_TEST_THREADS=1`.
- [ ] Run `just test-kernel`, both clippy gates, formatting, domains, debt, and contract-change with durable logs and exact exit codes.
- [ ] Confirm clean status and report all RED/GREEN evidence.
