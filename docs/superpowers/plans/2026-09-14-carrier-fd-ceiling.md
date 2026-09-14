# Carrier FD Ceiling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Remove host exits for definitely invalid fstat descriptors while preserving all Linux-visible policy and descriptor semantics.

**Architecture:** FileTables share a kernel-owned monotonic ceiling authority. Owned backend publishers mirror it into the carrier-global EL1 read-only control mapping before descriptor insertion. A separate fail-closed gate disables this optimization for any policy requiring host dispatch; no per-thread table rebinding is required.

**Tech Stack:** Rust, AArch64 instruction emitter, HVF signed guest tests, Docker arm64 oracle.

**Spec:** docs/superpowers/specs/2026-09-14-carrier-fd-ceiling-design.md

## Global Constraints

- No changed guest limits, tests, timeout, oracle flags or transport default.
- Source work only in this integration worktree; root owns signed builds and all guest runs.
- Red-first evidence, signed probes -> smoke -> full2127; preserve unrelated dirt, no push.
- Kernel authority has no HVF pointer or process-global static.
- A publisher must own its mapping backing for its entire lifetime.

## Task 1: Publication authority and FileTable wiring

Files: new carrick-hal/src/fd_ceiling.rs and export in lib.rs; new carrick-runtime/src/kernel/fd_ceiling.rs and export; kernel/objects.rs and kernel/core.rs constructor wiring.

Interfaces:
```rust
pub trait FdCeilingPublisher: std::fmt::Debug + Send + Sync {
    fn raise(&self, maximum: u32);
    fn disable(&self);
}
// Kernel authority public behavior; synchronization remains private.
impl FdCeilingAuthority {
    pub fn new() -> Self;
    pub fn publish(&self, fd: i32);
    pub fn register(&self, publisher: Arc<dyn FdCeilingPublisher>);
    pub fn disable(&self);
}
```

- [ ] Write a mock publisher and tests asserting raise occurs before install/guard visibility, registration receives existing maximum, and disable survives later registration.
- [ ] Run focused host tests before implementation and retain red receipt.
- [ ] Implement authority with serialized registration/publication; max starts2, never decreases. Register applies prior disabled state before exposing a publisher. Infallible callbacks only perform owned atomic updates; no callbacks into FileTable locks.
- [ ] Wire shared authority through boot/new roots, fork, exec and unshare copies. Keep legacy standalone FileTable::new callers safe with independent authority; all guest tables use Kernel authority.
- [ ] Run focused tests for isolation, constructors, copy paths and concurrent insertion. Review actual diff before commit.

## Task 2: Carrier control mapping and typed lowering

Files: carrick-hal threaded engine hook; carrick-vmm-hvf trap/persistent_executor.rs, mapping_plan.rs and hvf_aarch64_engine.rs; carrick-mem memory.rs fixed layout and mapping tests.

- [ ] Add mapping audit tests that reject absent/wrong-permission control backing and distinguish sharing from a copied snapshot.
- [ ] Reserve a nonoverlapping carrier-global kernel-only page. Include it in persistent mapping extraction, audit, task root projection, VM rebuild and exec replay. Initial word is fail-closed.
- [ ] Implement an owned publisher over that exact mapping: atomic fetch_max Release for ceiling, atomic closed-gate Release for permanent disable. Its Arc owns mapping lifetime. No raw borrowed pointer escape.
- [ ] Add an optional engine hook returning Arc<dyn FdCeilingPublisher>; unsupported backends return None. Register kernel authority before enabling guest use; all container roots in a carrier share the same backing.
- [ ] Test mapping permissions, independent carriers, replay and owner lifetime.

## Task 3: Policy-safe AArch64 fast return

Files: carrick-mem memory.rs emitter; runtime dispatch/seccomp_observer.rs, proc.rs, container_policy.rs; runtime vcpu_loop initialization/entry hook.

- [ ] Write red tests preserving x0..x5 on fallback, signed i32 fd decoding, policy-denied fstat and absent backing.
- [ ] Add fstat80 guard before the identity shim can clobber argument x0. Save/restore scratch registers under existing vector ABI; acquire-load valid gate and ceiling; only above-ceiling returns -EBADF. In-range/uncertain always follows original host path.
- [ ] Disable the carrier ceiling before guest-visible seccomp policy publication and before attaching any interceptor/observer/budget that requires host dispatch. One-way carrier-wide disable is permitted as a conservative loss of speed; it cannot reenable on a later root.
- [ ] Explicitly add fstat to policy eligibility; never infer permission from identity syscalls. Maintain accounting and asynchronous signal/CPU-limit delivery; use host fallback where unproven.
- [ ] Prove forced gate failure cannot bypass policy and continuously executing fastcalls can still receive signals/CPU limits.

## Task 4: Signed semantic and exit-count evidence

Files: existing conformance-next fixture/probe integration and committed source-hash oracle inventory.

- [ ] Add bounded probes for high valid/invalid fd, fork/exec/unshare/CLONE_FILES, fallback arguments, seccomp, signals and CPU limits. Preserve normal limits.
- [ ] Demonstrate red against deliberately broken publication or gate variant, then green on candidate for both libcs with negative entitlement controls.
- [ ] Count host exits separately from timing: above-ceiling avoids exits; valid/in-range/policy calls remain observable. Zero trace events is not accepted as proof without positive controls.

## Task 5: Impact and full closure

- [ ] Same-image serial ABBA of reducer and unmodified descriptor tests; compare output and timing, record exact source/binary/image and ambient load.
- [ ] Appropriate host fmt/runtime/integration/clippy/domain gates; repair only real failures, no ceilings raised to hide drift.
- [ ] Freeze clean signed CLI: source SHA, binary SHA, CDHash, UUID, entitlement, nonempty DOF and scoped cleanup.
- [ ] Public probes -> smoke -> full2127 with exact row accounting and fresh Docker oracle phase. Stop promotion at first red. Goal remains open until all requirements pass.

## Rulings

- Existing user authorization selects Sol/Terra subagents; no additional execution-choice question.
- Carrier-wide permanent disable on restrictive policy is a conservative fallback, avoiding per-thread policy rebinding and ignored guest-memory-write failures.
- Implementation details may be refined after actual mapping-code inspection; every spec invariant remains binding.
