# Native Child Signals, Waits, and Reparenting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close issue #786 by composing ARM native fork children with the existing shared signal, wait, exit, reap, and reparent owners.

**Architecture:** Route the ARM signal syscall family into the existing `ProcessSignals` implementation on `NativeProcessEntry`; do not create an ARM-only signal or lifecycle owner. Prove the route through production ARM dispatch, then bind the already shared native owner’s exact-generation wait/terminal/reparent witnesses into the two named contracts.

**Tech Stack:** Rust 2024, `no_std` EL1 code, `carrick-signal-core`, `carrick-sched-core`, VM-free ARM process fixtures.

**Spec:** `/tmp/design-740.md` and https://github.com/carrick-sh/carrick/issues/786

## Global Constraints

- Linux authority is `signal(7)`, `sigprocmask(2)`, `sigsuspend(2)`, `sigwaitinfo(2)`, `kill(2)`, `wait(2)`, `wait4(2)`, `waitid(2)`, `exit(2)`, and `PR_SET_CHILD_SUBREAPER(2)`.
- Guest signals, identity, waits, reaping, and reparenting remain in-zone and use shared `no_std` owners; no host answer or copied ARM implementation.
- A blocked guest wait releases execution capacity through one owned continuation; no polling, timeout widening, retry, or duplicate completion.
- Zombie readiness follows exact MM retirement, reap consumes once, and parent exit reparents to the exact live subreaper/init generation.
- Exit reservations retain late Born/ExitedInZone publication capacity without closing live participant membership gates.
- Do not change the crossing allowlist or exec internals.
- Do not raise the checked EL1 stack above 12,175 bytes; box or borrow any retained aggregate.
- Keep the layer below approximately 4,000 changed lines.

## Review Focus

- A parent signal arriving after child wait enrollment must wake the exact child continuation once and restore the temporary signal mask.
- A signal arriving during a service wait must retain both the service operation and pending signal without replaying either completion.
- Exit and signal-death wait statuses must use Linux numeric encodings; WNOHANG returns zero while live, and a consumed zombie returns ECHILD (10) thereafter.
- Parent exit racing delayed child retirement must notify and wake the current adopter, never the departed parent.
- Group exit with two live threads and late lifecycle publication must preserve terminal custody until every exact receipt settles.

---

### Task 1: Route ARM Native Signal Calls Through the Shared Owner

**Files:**
- Modify: `crates/carrick-personality-linux/src/dispatch.rs`
- Modify: `crates/carrick-el1-linux/src/aarch64_process_tests.rs`

**Interfaces:**
- Consumes: `route_shared(ordinal, allocator_control) -> Family` and `NativeProcessEntry: ProcessSignals`.
- Produces: ARM `Family::Signal` routing for kill/tkill/tgkill, rt_sigsuspend, rt_sigpending, rt_sigtimedwait, rt_sigqueueinfo, and rt_tgsigqueueinfo.

- [ ] **Step 1: Replace the existing “stays unported” assertion with a production-route test covering ordinals 129, 130, 131, 133, 136, 137, 138, and 240.**

- [ ] **Step 2: Run the focused test and retain the expected RED: ordinal 133 (and peers) are `Family::Unported`.**

- [ ] **Step 3: Remove the ARM-only unported override so these calls use `route_shared`; keep pidfd and crossing policy unchanged.**

- [ ] **Step 4: Run the focused route and ARM signal setup tests; expect PASS.**

- [ ] **Step 5: Commit with the issue-linked Why/What/Verified body and exact Codex trailer.**

### Task 2: Bind Native Signal-Wait and Terminal Composition

**Files:**
- Modify: `crates/carrick-el1-linux/src/aarch64_process_tests.rs`
- Modify: `crates/carrick-el1-linux/src/native_process_runtime.rs` only if a missing behavioral assertion requires it
- Modify: `conformance-contracts/contracts/el1-signal-delivery-owner.toml`
- Modify: `conformance-contracts/contracts/native-child-terminal.toml`

**Interfaces:**
- Consumes: production ARM dispatch, `NativeProcessRuntime` signal wait continuation, shared wait owner, terminal retirement owner, and reparent projection.
- Produces: contract bindings for child sigsuspend wake, exit/signal status, WNOHANG, single reap, adopter notification, two-thread group exit, and late lifecycle publication.

- [ ] **Step 1: Add a production ARM-dispatch witness that enters an owned signal wait and verifies the call suspends instead of forwarding/refusing. Name the production route mutation it catches.**

- [ ] **Step 2: Run it before any additional production change; expect RED on the unported base, or record that Task 1 is the minimal implementation making this later witness green.**

- [ ] **Step 3: Extend status/reap assertions only where the existing native tests do not already prove literal Linux errno/status values and exactly-once consumption.**

- [ ] **Step 4: Register exact VM-free bindings in both contract descriptors, including existing reparent, two-live-thread, and late Born/ExitedInZone tests. Do not claim signed or Docker evidence.**

- [ ] **Step 5: Run focused ARM/native owner tests and the contract registry checks; expect PASS.**

- [ ] **Step 6: Commit with the issue-linked Why/What/Verified body and exact Codex trailer.**

### Task 3: Portable and EL1 Budget Gates

**Files:**
- Create: `/tmp/740-s5-handoff.md` (untracked handoff)
- Modify: only files needed for test-derived fixes

**Interfaces:**
- Consumes: Tasks 1–2 branch.
- Produces: portable gate evidence, both EL1 image size/stack reports, changed-line boundary, and rebase handoff for slice 4.

- [ ] **Step 1: Run focused tests and `just test-kernel`; run `just test-loom` only if concurrency code changed.**

- [ ] **Step 2: Run `just clippy`, `just clippy-linux`, `just cross-check-macos`, `just fmt-check`, `just lint-domains`, and `just check-contract-change <main> HEAD`, all with the requested wrapper/cache environment.**

- [ ] **Step 3: Build both EL1 images and record loaded/raw size plus maximum checked stack. Stop if the stack exceeds 12,175 bytes.**

- [ ] **Step 4: Review `git diff` for exec/crossing/out-of-fence changes and confirm the layer remains below approximately 4,000 changed lines.**

- [ ] **Step 5: Write `/tmp/740-s5-handoff.md`, commit any final tracked corrections, and post the review-ready SHA without pushing.**
