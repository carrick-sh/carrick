# Authority-Enforced Kernel Closure Roadmap

**Controller:**
[`../specs/2026-08-19-authority-enforced-kernel-closure-design.md`](../specs/2026-08-19-authority-enforced-kernel-closure-design.md)

**Goal:** Complete the approved host-containment, Linux-conformance, and
lifecycle-performance campaign without collapsing its independently reviewable
subsystems into one unexecutable plan.

## Rules of the campaign

- The canonical completion lane is macOS/Apple Silicon/HVF/HVPatch with a Linux
  arm64 guest.
- The frozen 2,127-suite closure surface and every applicable arm64 musl/GNU
  probe remain the minimum regression denominator.
- Guest semantic authority stays in Carrick's kernel. Host access is limited to
  explicit backing or substrate capabilities.
- Conformance remains first. A valid completing row at or above 10x Docker is a
  correctness blocker.
- Fork/wait/exit, clone/join, signal delivery, and signal interruption require
  paired median and p95 confidence-bound ratios no greater than 1.0x Docker
  through 1,000 tasks.
- Every phase produces a durable report bound to one exact signed artifact.
- A phase report, green CI, or a focused MATCH does not complete the campaign.

## Plan sequence

| Phase | Plan | Independent deliverable | Exit boundary |
|---|---|---|---|
| 0 | [`2026-08-19-trustworthy-authority-baseline.md`](2026-08-19-trustworthy-authority-baseline.md) | Deterministic offline linting, explicit syscall authority, reviewed host-transition inventory, and a fresh signed closure baseline | The current boundary is honest and drift-gated; no security or conformance closure claim |
| 1 | Structural authority plan, written after Phase 0 | Typed handler contexts and named backing/substrate capabilities | Guest handlers cannot reach ambient or semantic host authority |
| 2 | Fork/wait/exit plan, written from the Phase 0 ledger | Asynchronous O(1) fork publication and kernel wait queues | No HVPatch host fork/wait/liveness fallback; relevant semantics exact |
| 3 | Thread/signal plan, written from Phase 2 measurements | Logical-task/carrier separation, targeted wake, generation-scoped cancellation | No guest-to-host signal targeting, broadcast wake, or missed interruption |
| 4 | Lifecycle fast-state plan, written from Phase 3 attribution | Per-thread fast state and removal of measured lifecycle cost | Every lifecycle family is no slower than Docker |
| 4 decision | M:N plan only on GO evidence | Optional resumable handlers and bounded carrier pool | Write only if parked carriers are the measured dominant residual; otherwise record KILL |
| 5 | Remaining kernel-object plan | Complete Guest/Hybrid authority ledger and expanded adversarial coverage | Zero semantic-host transitions for Guest rows; only declared Hybrid transitions |
| 6 | Exact closure plan | Close every suite, probe, crash, timeout, skip, and missing-result gap | Two exhaustive exact passes are ready on the final candidate |
| 7 | Final performance/containment audit plan | Controlled lifecycle/ecosystem performance plus hostile-input review | Every design completion requirement passes on one unchanged artifact |

## Phase-boundary update protocol

At each phase boundary:

1. Record source HEAD, binary SHA-256, CDHash, LC_UUID, entitlement, and
   `__dof_carrick` presence.
2. Record the exact commands, run IDs, raw artifact hashes, cleanup receipts,
   and whether Docker was live or cached.
3. Update the current conformance and authority ledgers from machine-readable
   results.
4. State which design requirements are proved, contradicted, or still missing.
5. Re-rank the next phase from fresh evidence rather than historical counts.
6. Keep the thread goal active until the final audit proves every requirement.

## Current state

- Approved design commits: `62041943b`, `82652169`.
- Phase 0 plan: ready for execution.
- Phases 1-7: deliberately not expanded into implementation steps until their
  required predecessor evidence exists.
