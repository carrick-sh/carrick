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
- Task 7: Ruling: the five-file list omitted acquisition of target-MM mutation
  authority and a carrier-owned target-ASID invalidator. A caller-MM
  pre-dispatch guard cannot authorize foreign COW, and `process_vm_writev`
  cannot select its target before dispatch. Task 7 therefore owns the minimal
  additional runtime/MM binding, exact target census/coordinator acquisition,
  and shared invalidation plumbing required to make its mandated facade usable
  end to end; Task 8 may consume that API but may not invent authority. It must
  not add process-vm to the current-MM classifier or fall back to the caller's
  active engine. Cost if wrong: Task 7 touches more files than listed, but the
  alternative either grants MM A authority over MM B or leaves the consumer
  task unable to satisfy the spec.
- Task 7: Ruling: target-ASID invalidation uses a two-phase page-table pause,
  not an async continuation or reserved maintenance vCPU. After target-active
  executors leave guest and admission closes, the coordinator edits stage-1,
  publishes the exact invalidation generation, waits for every active target
  owner-vCPU acknowledgement while they remain excluded, then commits or rolls
  back. Inactive/resident executors record the generation and must service it
  before next guest entry with that exact target binding, so the foreign caller
  never waits on its own command while running another MM. Cost if wrong: this
  expands the existing pause/executor protocol and adds a mandatory pre-entry
  generation check; the rejected alternatives either deadlock at one vCPU,
  consume product capacity, or defer the entire syscall through a new scheduler
  continuation architecture.
- Task 7: review round 0 rejected `1bef8eb51` on six load-bearing findings:
  production snapshot reacquisition under alias mutation, recoverable failure
  after irreversible inventory publication, a mutex on ordinary guest re-entry,
  raw invalidation identity domains, incomplete mapping/frame/owner receipt
  authentication, and tests that bypass production authority composition. Fix
  round 1 resumed the original implementer from base `1bef8eb51`.
- Task 7: minor (deferred): the new stage-1 and pause invalidation generation
  counters use wrapping increment and can eventually reuse stale identity; the
  final whole-branch review must decide whether checked fail-closed exhaustion
  is required before integration.
- Task 7: implementation complete and awaiting independent approval. The
  canonical facade acquires a real exact-target mutation guard, mints a
  single-use opaque `CowBroken`, revalidates token/range/three revisions and
  owner generation before both COW and copy, and reuses the production HVF COW
  transaction plus byte-exact rollback pre-image. Exact-ASID invalidation is a
  two-phase active-owner acknowledgement with a mandatory inactive/resident
  pre-entry generation gate; the backend never reacquires PtPause or uses the
  caller engine. Fresh gates: HAL foreign-MM 1/1, runtime MM access 18/18,
  runtime HVPatch 109/109, HVF foreign-COW 3/3 and frame-COW 1/1, thread 53/53,
  serialized runtime 2,090/2,090, serialized HVF 279/279, workspace check,
  targeted clippy, checker self-test 20 negative/17 positive, format and diff
  checks. Production checker remains intentionally RED with exactly the one
  Task 8 `foreign-current-memory` finding in untouched `dispatch/proc.rs`.
  Report: `task-7-report.md`.
- Task 7: fix round 1 commit `021e8df0b` addressed review findings 1-4 and the
  deferred generation-wrap concern, but scoped re-review rejected findings 5
  and 6. The transport's public live-inventory trait still self-attests both
  sides of the receipt comparison rather than carrying an independently sealed
  kernel-authority proof, and the production/topology coverage still composes
  mock transport and an unrelated local scheduler instead of driving the real
  carrier COW path through budget-one/full-occupancy and concurrent target
  exec/retirement. Fix round 2 resumed the original implementer from
  `021e8df0b`; scope is limited to those two findings and fix-introduced
  breakage.
- Task 7: fix round 2 commit `ff97d9a95` addressed the production-composition
  finding, including the real carrier transport, capacity-one scheduler,
  active/inactive invalidation paths, CLONE_VM, and concurrent exec/retirement.
  Scoped re-review retained one authority defect: the kernel proof issuer
  independently authenticates MM/revision/mapping/frame/extent but embeds an
  owner generation supplied by the transport, so the transport can use the
  issuer as a signing oracle for an internally consistent wrong owner. Fix
  round 3 resumed the original implementer from `ff97d9a95` and is limited to
  independent current-owner authentication plus its regression and gates.
- Task 7: complete and independently approved at canonical `d7688a2e5`.
  Review round 3 accepted the engine-bound canonical owner-directory view: the
  transport-callable proof issuer no longer accepts owner generation, retains
  and rechecks the exact existing owner `Arc`, and embeds only the independently
  authenticated generation. The final signing-oracle and self-consistent
  wrong-owner regressions are green, with no new review breakage. Final fresh
  gates: runtime 2,104/2,104, HVF 280/280, thread 54/54, HAL 111 unit plus two
  compile-fail doctests, AArch64 32/32, focused production-carrier and foreign
  COW suites, workspace check, targeted clippy, checker self-test 20 negative/
  17 positive, format, and diff checks. The production checker remains
  intentionally RED with exactly the Task 8 `dispatch/proc.rs:4425` consumer
  finding. Report: `task-7-report.md`.
- Task 8 clean-room reset, 2026-08-29: the first process-vm implementation
  stream and one permission-review stream are abandoned because Linux kernel
  source was consulted during their reasoning. No Task 8 candidate reached
  `main`; reviewed `main` remains the Task 7 milestone `a8c3e1864`. Work restarts
  from that exact commit on `codex/fd-description-cleanroom`. From this point,
  no agent may open, search, quote, cite, or rely on Linux kernel source or on
  findings from the abandoned streams. Linux-visible behavior must be derived
  only from Carrick's checked-in contracts, public ABI documentation, and
  controlled Docker-oracle measurements. Old branches/worktrees are retained
  as non-integrable evidence so their commits cannot be mistaken for clean-room
  candidates.
- Task 8 clean-room read slice: native-arm64 Docker receipt `c65ad4234`
  established intra-iovec 4096-byte prefix behavior and zero-transfer/error
  ordering without Linux kernel source. Codex-owned RED commit `ca7ab5b5d`
  distinguishes caller bytes `SELF` from exact foreign bytes `PEER` and records
  the oracle ordering. Focused pre-fix result is 4 green / 2 RED: foreign read
  returns EFAULT instead of four target bytes, and zero-local input imports the
  invalid remote vector instead of returning zero. Antigravity worker
  `process-vm-read-cleanroom` was dispatched from that exact commit in isolated
  worktree `.worktrees/agy-process-vm-read-cleanroom`, run id
  `mm-authority-cleanroom-20260829-task8-read`, conversation
  `7af91b24-43aa-483b-9ecf-e60854fdcabf`. Scope is borrowed exact execution
  authority, ordering, and foreign reads only; writes, permissions expansion,
  ptrace, and proc-mem are excluded.
