# SDD ledger — plan: docs/superpowers/plans/2026-08-28-mm-authority-lock-order.md

Spec: `docs/superpowers/specs/2026-08-28-mm-authority-lock-order-design.md`

Base integrated milestone: `805d1478b`

Design commit: `fb126d758`

Plan commits: `27aa7f2e1`, preflight correction `35fe92892`

Policy: independently reviewed GREEN milestones fast-forward local `main`;
RED and review-pending commits remain on `codex/fd-description-seam`; no push.

## Preflight task consistency

| Task | Internal agreement | Ruling |
|---|---|---|
| 1 | Checker fixtures, RED scan, justfile wiring, and commit all name the same six authority classes; preflight adds blanket-current-impl as a seventh behavioral class. | Clean after correction. |
| 2 | Creates a test-bearing `mm_access.rs` before APIs exist and requires compile failure on those missing APIs. | Intentional RED; do not make production compile in Task 2. |
| 3 | Files, interfaces, VMA projection, token minting, focused tests, and commit agree. | Clean. |
| 4 | Original Step 1 mandated a self-source grep, conflicting with the good-test rule. | Ruling: replace it with Task 1 behavioral checker fixtures for blanket impls; source text is not a Rust unit-test oracle. |
| 5 | HAL DTOs, shared state, backend read tests, facade, and gates agree. | Clean; transport data is not safe authority. |
| 6 | Original design omitted how real pause authority reached handlers. The approved spec/plan correction said to thread `MmMutationGuard` through every `SyscallCtx`, but ordinary threaded syscalls intentionally own neither `PtPauseGuard` nor `Stage1Exclusive`; granting either would be false authority or impose a page-table pause on the hot path. | Ruling: split dispatch by structural typestate at the outer resolver. Only the statically classified alias-capable path receives a real guard minted from the actual pre-dispatch pause/exclusivity authority; ordinary contexts use a distinct type that cannot obtain `HostAliasPermit`. No optional/runtime-enum/fake guard is accepted. The classifier must agree exactly with the pre-dispatch stage-1/pause decision and fail closed under tests/source enforcement. |
| 7 | COW tests, transport, shared-state factoring, guard borrowing, witness mint/consume, and gates agree. | Clean after Task 6 correction; backend must not reacquire PtPause. |
| 8 | Process-vm and ptrace share `dispatch/proc.rs`. | Ruling: workers A and B are serialized on successive canonical bases; proc-mem may run independently only while file-disjoint. |
| 9 | Probe, oracle, pre-fix RED, post-fix GREEN, LTP, and commit agree. | Clean; exact harness command may be adjusted only to the repository's current filter syntax with a ledger ruling. |
| 10 | Source census, full gates, two reviews, receipts, fast-forward, and scoped cleanup agree. | Clean; full audit remains active if completion audit finds another open requirement. |

## Cross-task interface scan

| Producer -> consumer | Shared file/interface | Result |
|---|---|---|
| 1 -> 3/4/6/8/10 | `check-mm-authority.py` categories and justfile gate | Later tasks close named categories; Task 10 proves zero. |
| 2 -> 3 | wished-for kernel MM APIs | Exact type/method names agree. |
| 3 -> 4 | `CurrentMmMemory` revision/VMA/token foundation | Task 4 only performs explicit marker census. |
| 3 -> 5/7/8 | `MmToken`, `MmRelation`, ranges, revision domains | Names and ownership agree. |
| 4 -> 5/8 | current-MM generic bounds | Foreign transport remains separate; no blanket bridge. |
| 5 -> 6 | `MmAccessState` plus shared page-table observer | Sequential shared edits in runtime/HVF files; Task 6 starts from reviewed Task 5 head. |
| 5 -> 7 | transport DTOs/read facade | Task 7 extends rather than replaces them. |
| 6 -> 7 | `MmMutationGuard` and `HostAliasPermit` | Task 7 borrows the pre-dispatch guard and cannot reacquire PtPause. |
| 7 -> 8 | `break_foreign_cow`, `CowBroken`, `write_foreign` | Consumer worker briefs use exact canonical signatures. |
| 8 -> 9 | observable syscall semantics | Probe assertions derive from Docker literals, not implementation helpers. |
| 1-9 -> 10 | source, test, binary, delegation, and review evidence | Completion receipt must enumerate each requirement and non-green condition. |

## Progress

- Design approved and committed: `fb126d758`.
- Plan committed: `27aa7f2e1`.
- Preflight correction committed: `35fe92892`; behavioral blanket-impl fixture
  replaces a forbidden self-source Rust assertion.
- Task 1: complete and independently approved at `626013f8f`; base
  `35fe92892`, implementation commits `f8ce9f125`, `71d890349`, and
  `626013f8f`, brief `task-1-brief.md`, report `task-1-report.md`. The
  executable checker passes 11 negative and 13 positive fixtures; the
  production tree remains intentionally RED with 246 findings. Review rounds
  fixed `#[cfg(test)]` item masking and impl/type-level generic-bound coverage.
- Task 2: complete and independently approved at `b222849ba`; base
  `626013f8f`, implementation commits `4d6f34062` and `b222849ba`, brief
  `task-2-brief.md`, report `task-2-report.md`. The focused no-run gate is
  intentionally RED with 16 Task-3-only API absences. Review strengthened
  token-only `Arc<Mm>` retention across exec and retirement, coherent revision
  churn rejection, cross-VMA permissions, zero-length semantics, and the
  distinct-task `CLONE_VM` precondition.
- Task 3: complete and independently approved at `0c4d584fd`; base
  `b222849ba`, implementation commits `cfda05192`, `e7ac246fe`, and
  `0c4d584fd`, brief `task-3-brief.md`, report `task-3-report.md`. Fresh serial
  gates: MM access 10/10, snapshot 11/11, dispatch memory 126/126, exact
  copied/`CLONE_VM` relation 1/1, thread execution 11/11. Review rounds added
  scheduler task-state authentication, removed raw public token accessors,
  proved token-only retention and expiry, and closed a same-key cross-kernel
  lease collision by authenticating the exact `Weak<Thread>` owner pointer.
  The source gate remains intentionally RED with 246 later-task findings.
- Task 4: Antigravity worker dispatched from exact base `0c4d584fd` in isolated
  worktree `/Volumes/CaseSensitive/carrick/.worktrees/agy-mm-current-census`,
  branch `agy/mm-current-census`. Run id
  `mm-authority-lock-order-20260829`, worker `mm-current-census`, conversation
  `e0695445-fb49-491b-8a13-fa3d4ed03831`. Preflight checker: 11 negative and
  13 positive fixtures; initial census: 33 `GuestMemory for` sites and 268
  generic/dynamic occurrences.
- Task 4: complete and independently approved at canonical `1af897dd7`.
  Antigravity conversation `e0695445-fb49-491b-8a13-fa3d4ed03831` ran three
  turns (32m33s, 2,528,006 tokens) and produced worker commits `279d9bbac`,
  `5db20ac6c`, `f99aae9fc`, cherry-picked canonically as `3db17ed4a`,
  `4b0548c64`, `57346b091`. After the worker hard cap, Codex-owned checker
  closure `1af897dd7` fixed generic implementation parsing and mixed current/
  foreign byte-access enforcement. Final census: 33 GuestMemory impls, 31
  explicit CurrentMmMemory impls, with only neutral `MockMem` and
  `HostWriteEvents` guest-only. Fresh gates: checker 20 negative/17 positive,
  workspace check, guest-memory 37/37, dispatch 643/643, HAL and generic engine
  scoped scans green. Full checker is intentionally RED with exactly six
  later-task findings. Report: `task-4-report.md`.
- Task 5: complete and independently approved at canonical `97bcd5f4d`.
  Prerequisite import correction `7a90640ab`; implementation `eaba7df84`;
  review repairs `6a5908345` and `97bcd5f4d`. Two review rounds closed exact
  `Arc<MmAccessState>` identity, retained old-MM physical backing through real
  exec retirement and binding reuse, live revision coupling, raw transport
  bypasses, structural owner receipts, executor-local failure injection, and
  real overall deadlines across every participating lock. Fresh independent
  gates: HAL foreign-MM 1/1, HVF foreign-MM 9/9, runtime MM access 14/14,
  runtime HVPatch 177/177, workspace check, focused clippy, compile-fail
  capability doctests, checker self-test 20 negative/17 positive, format and
  diff checks. Full checker is intentionally RED with exactly four later-task
  findings: one foreign-current-memory, one legacy-lock-order, and two
  unpermitted-host-alias. Report: `task-5-report.md`.
- Task 6: complete and independently approved at canonical `44cae1833`.
  Structural implementation and delegated repair commits: `ebdad5c9b`,
  `8c9d2c8e`, `5edfee5ae`, and `32ae993ec`; Codex-owned full-gate closure
  `63a1d9d87`; final exact-MM pause-provenance repair `44cae1833`. Independent
  review first rejected MM-agnostic nested frame-COW authority, ordinary-route
  mutation fixtures, and a stale registration contract; the immutable-range
  review then rejected caller-paired pause/MM/coordinator identity and the
  ThreadId-derived test MM. The accepted path owns a same-thread exact-MM lease,
  derives paused mutation identity solely from the linear participation lease,
  structurally publishes boot/VMA and fork-install state under host-alias
  authority, and contains no fake mutation issuer. Fresh gates: mutation 2/2,
  exact pause 16/16, process-fork 17/17, serialized runtime 2,083/2,083, full
  repository `just test`, checker self-test 20 negative/17 positive, workspace
  check, targeted clippy, format, and diff checks. The production checker is
  intentionally RED with exactly the one Task 8 `foreign-current-memory`
  finding. Report: `task-6-report.md`.
