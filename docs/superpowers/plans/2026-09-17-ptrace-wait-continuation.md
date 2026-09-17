# Ptrace wait continuation implementation plan

> **For agentic workers:** Use the existing Antigravity worker review workflow. The director owns diagnosis, integration, and acceptance.

**Goal:** A legal wait for a non-child tracee must park and report its ptrace stop without terminating the carrier.

**Architecture:** The wait operation already recognizes exact tracer ownership; continuation construction must preserve that contract. Retain exact task generations, the scan-time wake precheck, and syscall redispatch as the authority for the returned wait result. The waiter task's wake queue already receives ptrace stop events.

**Tech stack:** Rust, public carrick-kernel API, carrick-kernel-example VM-free backend, native ARM64 Docker, signed HVF carrier.

**Spec:** `docs/perf-results/2026-09-17-socket-conformance-batch.md`, remaining priority 1. LTP ptrace11 attaches PID 1, waits for its stop, then detaches.

## Constraints

- Preserve unrelated plans, exact generation authentication, wait4/waitid semantics, and ordinary ECHILD results.
- No sleep-based interleaving, retries as acceptance, timeout increases, serialization fixes, or concurrent Carrick/Docker phases.
- Workers use an isolated worktree; director verifies their actual diff and tests.

## Task 1: Deterministic reproduction and fix

Files: create `crates/carrick-kernel-example/tests/ptrace_wait.rs`; modify the process-wait branch of `crates/carrick-kernel/src/kernel/continuation.rs` and its owner accessor only if necessary.

- [x] Drive PTRACE_ATTACH and actual wait dispatch through public backend/kernel APIs before stop settlement; prove continuation construction fails on source 1fa517693. Director verified four failures and two passing controls; test commit `6fcf9e831`.
- [x] Cover sibling and ancestor/root tracees, wait4 and waitid; retain unrelated ECHILD and ordinary-child controls.
- [x] Preserve the same scan-time precheck across stop-before-enrollment and stop-after-enrollment; assert the returned stop status and detach behavior.
- [x] Fix the parent-only validation using exact tracer ownership; avoid numeric-ID relookup across authority snapshots. Review lifecycle race implications before accepting the implementation.
- [x] Preserve typed ptrace-stop provenance through event consumption, the wait receipt, and waitid rendering. Native Docker returns CLD_TRAPPED (4), while ordinary job-control stops return CLD_STOPPED (5). Signed baseline diagnostic `conf-66293` reports 5 and fails; Docker reports 4 and passes. Add both controls rather than encoding Carrick's old answer in a test.
- [x] Run `RUSTC_WRAPPER= cargo test -p carrick-kernel-example --test ptrace_wait`, `RUSTC_WRAPPER= just test-kernel`, and formatting. Review and commit the bounded change.

## Task 2: Integration and signed evidence

- [x] Run `RUSTC_WRAPPER= just ci` after integrating and reconciling any position-only inventories.
- [x] Build/sign once, record source, SHA-256, CDHash, LC_UUID, entitlement, and DOF; preserve the signed artifact.
- [x] Run deterministic tests and a predetermined live ptrace11 sample against the original and corrected artifacts. Native Docker must independently pass; sample results do not replace deterministic coverage.
- [x] Run signed probes, then smoke, then full on the same artifact, preserving failures and raw streams. Do not claim full closure if any row fails or metadata is incomplete.
- [x] Record results and remaining defects in a dated report, prove scoped cleanup, commit locally, and leave no push.

## Review checkpoint

Integrated worker commits `6fcf9e831` and `c349748fa` into main. The director independently verified all 16 ptrace tests. The final worker also passed the normal partitioned kernel recipe with regular-file output. Stop-before-wait, stop-between-scan-and-enrollment, and stop-after-enrollment are covered for ancestor/root and sibling tracees across wait4 and waitid. Typed `StopKind` preserves provenance. The Unix credentials test now checks payload-to-sender correspondence without assuming child scheduling order.

Worker console/resource failures and the earlier false sender-order assertion are preserved in `target/conformance/eco-ptrace-20260917/worker-final.jsonl`; passing retries were not accepted as their resolution. Independent unchanged-base and candidate kernel runs passed with complete regular-file output. Standing user authorization covers Antigravity use. Independent read-only review found no introduced defects. Full CI passed (5,507 passing executions, five existing ignores). The pinned signed artifact passed probes and fresh-oracle smoke; full closure completed red (1,263 MATCH / 864 INCOMPLETE), with complete row and run-ID populations. The live waitid reduction matches Docker and the predetermined ptrace sample is 9/10 original versus 10/10 corrected.

Final receipt: [ptrace wait batch](../../perf-results/2026-09-17-ptrace-wait-batch.md).
Full closure remains red; the completed batch does not claim release readiness.
