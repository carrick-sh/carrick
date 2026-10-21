# First-Entry Ownership Implementation Plan

> **For Codex:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make first-entry placement, activation, and retirement mutually exclusive through the scheduler record's existing atomic claim word.

**Architecture:** Extend `Claim` with activation and retirement states and expose only typed transition tokens. Closing treats activation/retirement as deferred ownership; producer placement first acquires an exact host-transfer token, and executor adoption retires through activation-to-retiring before storage becomes free. Test-only bounded hooks pause the real producer and executor paths at the two reviewed race windows.

**Tech Stack:** Rust, carrick-sched-core lock-free claim state machine, carrick-kernel EL1 zone, carrick-runtime executor tests.

---

### Task 1: Add red production-path witnesses

**Files:**
- Modify: `crates/carrick-runtime/src/vcpu_loop/executor.rs`
- Modify: `crates/carrick-kernel/src/el1_zone.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/binding.rs`

Add bounded test hooks at executor take-before-adopt and producer admit-before-place. Exercise Closing through production routing, adoption through `next_runnable`, and assert single delivery/retirement and queue integrity. Add repeated and concurrent mint coverage. Run against `9f0c5f3719` and record the bounded failures.

### Task 2: Replace split activation ownership with claim states

**Files:**
- Modify: `crates/carrick-sched-core/src/lib.rs`
- Modify: `crates/carrick-kernel/src/el1_zone.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/executor.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/threads.rs`

Document every ownership state and operator. Add exact CAS transitions and typed placement, activation, and retirement tokens. Delete the handback activation marker, unlocked queue scan, and predicate APIs. Make Closing defer to active ownership, placement authenticate its token, mint accept only Host, and retirement exclude publication until free completes.

### Task 3: Exhaustively verify the transition protocol

**Files:**
- Modify: `crates/carrick-sched-core/src/lib.rs`

Add a table covering every state/operation pair with the exact success state or rejection. Run focused scheduler, kernel, runtime, and Linux-personality tests.

### Task 4: Gate and commit

Run the requested serial crate suites and all six repository gates with sccache disabled. Commit the red witness separately from the fix, with Why/What/Verified and `Co-Authored-By: GPT-6.1 Sol <noreply@openai.com>`.
