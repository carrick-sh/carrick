# NativeLane Seam — Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Neutralize the x86 lane's inline memory model (`IdentityGuestMemory` + support machinery → a shared identity-memory module keyed on lane traits) and adopt the shared `TranslationCache` in the x86 lane — the two moves that make a NetBSD/aarch64-or-x86 native lane a host-glue exercise instead of a fourth monolith — plus the Phase-1 carry-ins.

**Architecture:** Continuation of the strangler campaign on `native_freebsd.rs` (19.7K lines) using the Phase-1 seams (`carrick_dsr::lane`, host crates, `native/` facade). Phase 2 deliberately excludes the thread-loop merge, exec-capsule adoption, and the cross-process futex trait (Phase 3): the generic loop needs both lanes standing on shared memory + cache types first — this phase builds exactly that floor. Every behavior-adjacent task carries the LTP-gate-equivalence acceptance proven in Phase 1.

**Tech Stack:** Rust workspace (1.96.0 pinned); FreeBSD box verification (root@fbsd, `--no-default-features --features platform-freebsd`); LTP gate `scripts/native-x86-ltp-gate.py` (invocation + fixtures per Phase-1 Task-4/Task-8 reports).

**Spec:** `docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md` (+ 2026-07-23 drift appendix). Phase-1 evidence: `docs/native-lane-seam-phase1-evidence.md`. Structural ground truth: the 2026-07-23 lane maps (section/line refs embedded per task; line numbers drift — locate by symbol).

## Prerequisites / branch policy

- Base: `main` ≥ `6e5d8efb` (Phase 1 + CI-health + mremap ruling all merged; deterministic `just ci` stages green).
- Branch: `feat/native-lane-seam-phase2`. FreeBSD leg BEFORE every commit; box commands need `. ~/.cargo/env` + the platform feature flags; restore the box branch after every use; STOP/BLOCKED if box dirty.
- Known pre-existing macOS residue (do NOT chase; stash/baseline-prove any new failure): the classified §3 flake cluster (main-health-report.md) and the tickets therein.

## Global Constraints

- **Behavior-preserving unless a task names its sanctioned change.** Behavior-adjacent tasks (2, 3) MUST show LTP-gate pass-set equivalence (before/after on the box, programmatic diff — the Phase-1 Task-4 protocol) in addition to suites.
- **No scattered target cfgs in shared code** (spec fixed decision). Host-specific behavior extracted from moved code goes behind `NativeHost`/host-crate seams, never inline `#[cfg]` in the shared module.
- **Process-global invariants stay** (RUN_LOCK, fixed arenas, IDENTITY_* statics scope): moving code does NOT mean parameterizing these — they remain documented shared constraints (Phase-1 ruling).
- **Clean-room**: man-pages/spec/oracle only; never Linux kernel source.
- Both platforms green per task BEFORE its commit: macOS `just fmt-check && just clippy` + targeted crate suites; FreeBSD box build + targeted suites (+ LTP gate where required).
- Logical commit per task with the standard trailers (`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` + the session `Claude-Session:` line). NEVER `--no-verify`.

## File Structure (Phase 2 end-state)

- `crates/carrick-dsr/src/identity_memory/` — NEW module (or single `identity_memory.rs` if it stays <3K lines): `IdentityGuestMemory`, identity checked-copy machinery, `NativeMapping`/`NativeMappingTransaction`, raw-range gate — POSIX-generic, lane-trait-parameterized where ISA/host facts are needed.
- `crates/carrick-dsr/src/lane.rs` — MODIFIED: whatever minimal trait surface Task 2 actually consumes (sized-to-consumption rule from Phase 1; expected: a host hook for shared-futex vnode keying and nothing more).
- `crates/carrick-native-freebsd/src/` — MODIFIED: FreeBSD-specific extractions (sysctl vmmap futex key, minherit vfork helpers) as host-crate functions the shared module reaches via the seam.
- `crates/carrick-runtime/src/native_freebsd.rs` — SHRINKS: memory model + cache scheme replaced by shared-module consumption (target: −3.5K lines or better).
- `crates/carrick-dsr/src/cache.rs` — possibly MODIFIED: whatever the x86 adoption genuinely needs (additive only; aarch64 lane untouched).
- Docs: evidence doc phase-2 section; spec drift appendix addition if shapes change.

---

### Task 1: Precision re-map + seam sizing (read-only scouting, committed as a doc)

**Files:**
- Create: `docs/superpowers/specs/2026-07-23-identity-memory-neutralization-notes.md`

Phase 1 shifted line numbers and the 2026-07-23 maps predate it. Before moving ~2K lines, re-inventory with precision. This task is read-only on code.

- [ ] **Step 1:** Map `IdentityGuestMemory`'s full closure in today's `native_freebsd.rs`: the struct + `impl GuestMemory` + private helpers (`ensure_identity_backed*`, `identity_apply_host_protection_preserving_bus`, `mapping_write_for_mutation`/`mapping_read_for_write`), `IDENTITY_PROTECTIONS`/`IDENTITY_HOST_MAPPING_LOCK` statics, `identity_raw_*` range gate, checked-copy cluster (`identity_kernel_copy*`, `identity_checked_*`, `IdentityXstateMemoryReader/Writer`), `NativeMapping`/`NativeMappingTransaction`/`map_prot_at`/`map_fixed_replacement`, `freebsd_shared_waiter_key`, and the `ControlFlowMemory` impl. For each item: exact current line range, and a disposition — MOVE-AS-IS (POSIX-generic), MOVE-BEHIND-SEAM (host-specific: name the seam method), or STAY (lane-specific, e.g. minherit vfork machinery stays; document why).
- [ ] **Step 2:** Inventory every use of the moved items from the rest of `native_freebsd.rs` (the consumers that will import from the new location) and any `#[cfg(test)]` fault-injection thread-locals wired into production fns (`NATIVE_MAPPING_FAULTS`, `IDENTITY_KERNEL_COPY_*`) — these must keep working post-move (they move with their functions).
- [ ] **Step 3:** Inventory the x86 cache scheme for Task 3: `CachedBlock`, `VaHasher`, `PublishedFaultEntry`, `PendingChainEdge`, `patch_slot`/`GuardedChainPatch`/`publish_guarded_chain_edge`, JIT slice accounting in `SharedRun` (`alloc_slice`/`free_slice`) — vs `carrick_dsr::cache::{TranslationCache, CacheWriter, PageGenerationTable, ConcurrentPublicationIndex}`: a capability matrix (what the shared cache has, what the x86 scheme needs that it lacks, what's genuinely per-lane). Disposition: ADOPT / EXTEND-SHARED (additive) / KEEP-LANE (justify).
- [ ] **Step 4:** Commit the notes doc — `docs(native): identity-memory + cache adoption precision map`. This doc is the binding input to Tasks 2-3; if it reveals the plan's shape is wrong (e.g. the cache adoption needs non-additive changes to the aarch64 path), STOP and escalate before Task 2.

---

### Task 2: `IdentityGuestMemory` → `carrick_dsr::identity_memory` (the NetBSD floor)

**Files:**
- Create: `crates/carrick-dsr/src/identity_memory.rs` (or module dir per size)
- Modify: `crates/carrick-dsr/src/lib.rs`, `crates/carrick-dsr/src/lane.rs` (minimal seam growth per Task-1 notes), `crates/carrick-native-freebsd/src/lib.rs` (+ new host fns), `crates/carrick-runtime/src/native_freebsd.rs` (imports + deletions), Cargo.tomls as needed
- Test: the module's inline tests move with it (incl. `identity_raw_range_tests`, ~1.5K lines); runtime consumers pin behavior; box integration + LTP gate = acceptance

Mechanics (per Task-1 dispositions — the notes doc governs where it conflicts with this sketch):
- MOVE-AS-IS items go verbatim (use-path edits only; `git mv` is impossible for a partial-file move — instead: extraction commit discipline = one commit, with the notes doc's line-range inventory as the audit trail, and `git diff --color-moved=dimmed-zebra` evidence in the report showing moved-not-rewritten bodies).
- Host-specific: `freebsd_shared_waiter_key` (sysctl KERN_PROC_VMMAP) moves to `carrick-native-freebsd`, reached via the seam method Task 1 sized (expected shape: `NativeHost::shared_futex_key(addr, len) -> Option<SharedFutexLocation>` or a narrower hook — the notes doc decides). The shared module contains ZERO `#[cfg(target_os)]`.
- The statics (`IDENTITY_PROTECTIONS`, `IDENTITY_HOST_MAPPING_LOCK`, `SHARED_WAITER_TABLE` if touched) move with the module but stay process-global — document the constraint in the module doc.
- `X86_64_USER_END_EXCLUSIVE` consumption switches to `L::Isa::USER_VA_END_EXCLUSIVE` where the moved code is lane-parameterized; the Task-1 (Phase-1) drift-pin test updates accordingly.

- [ ] **Step 1 (RED):** Before moving, capture the baseline: on the box, run the full `native_freebsd_x86` suite + the LTP gate case list; record pass-sets (this is the equivalence baseline).
- [ ] **Step 2:** Execute the move per the notes doc. Compile-driven: `cargo check -p carrick-dsr` then `-p carrick-runtime` (box) iteratively.
- [ ] **Step 3:** macOS: `cargo test -p carrick-dsr --lib` (moved tests green — note: identity tests that genuinely require FreeBSD host behavior get the same treatment as the crate's other target-gated tests; the notes doc lists which), `just clippy`, runtime lib suite (flakes stash-proven only).
- [ ] **Step 4:** Box: full `native_freebsd_x86` + LTP gate; pass-sets MUST equal Step-1 baseline (programmatic diff). Any delta = STOP, diagnose, fix or escalate.
- [ ] **Step 5:** Metrics snapshot for the report: `native_freebsd.rs` line count (expect ≈ −2K), `identity_memory.rs` line count.
- [ ] **Step 6: Commit** — `refactor(dsr): neutralize identity guest memory into carrick-dsr`

---

### Task 3: x86 lane adopts the shared `TranslationCache`

**Files:**
- Modify: `crates/carrick-runtime/src/native_freebsd.rs` (CachedBlock scheme → shared cache), `crates/carrick-dsr/src/cache.rs` (ADDITIVE-only extensions per Task-1 matrix), tests both sides

Per the Task-1 capability matrix. Constraints: the aarch64 lane's cache behavior must be untouched (its suites + the DSR oracle tests are the pin); extensions to the shared cache are additive with their own unit tests; if the matrix says the x86 chain-edge publish protocol (`publish_guarded_chain_edge` target-first ordering) can't map onto `ConcurrentPublicationIndex` without semantic change, KEEP-LANE that piece and adopt the rest — partial adoption with a documented boundary beats forced unification (record what stayed and why).

- [ ] **Step 1 (baseline):** Same as Task 2 Step 1 (fresh baseline at current HEAD).
- [ ] **Step 2:** Adopt per matrix; iterate on the box (`cargo test -p carrick-runtime --test native_freebsd_x86 --no-default-features --features platform-freebsd` slices while working).
- [ ] **Step 3:** macOS: dsr crate suites + DSR oracle tests (`cargo test -p carrick-runtime --lib dsr 2>&1 | tail`) — aarch64 cache path proven untouched; clippy.
- [ ] **Step 4:** Box: full suite + LTP gate equivalence vs Step-1 baseline.
- [ ] **Step 5: Commit** — `refactor(runtime): adopt shared TranslationCache in the x86 native lane`

---

### Task 4: Carry-in smalls (one commit each, batched dispatch)

**Files:** as listed per item.

- [ ] **(a)** `fork_child_rebuild`: `fault::register_code_region` must take the new region's `capacity` instead of the local `cache_len` const (drift-hardening; Phase-1 final-review Minor #4). Test: existing fork suites on box. Commit: `fix(runtime): register fork-child code region by actual capacity`.
- [ ] **(b)** Remove `NativeHostJit::after_fork_child` (proven never-called; the real repair is `TranslationCache::after_fork_child` → `end_thread_write`). All 7 impls drop it; doc the removal in host.rs referencing the Phase-1 finding. If ANY production call site is discovered (re-grep first!), STOP → escalate instead. Commit: `refactor(dsr): remove dead after_fork_child from the jit seam`.
- [ ] **(c)** `GuestIsa::GUEST_PAGE_SIZE` — decide with evidence: grep consumers; if still zero production consumers, REMOVE the const (YAGNI; the capability table in `page_profile.rs` is the real geometry authority — cite the linux4k counter-example in the removal commit). If consumers appeared, move the fact behind the capability table instead. Commit: `refactor(dsr): page geometry belongs to the capability table, not GuestIsa`.
- [ ] **(d)** `native_darwin` cfg-gating gap (SIGILL on FreeBSD unscoped `--lib`): gate the module the same way `native_freebsd` is gated (`#[cfg(all(target_os = "macos", target_arch = "aarch64"))]` at the decl in lib.rs) + fix any newly-dead cross-references that gate exposes. Verify: box `cargo test -p carrick-runtime --lib --no-default-features --features platform-freebsd 2>&1 | tail -3` no longer SIGILLs. Commit: `fix(runtime): cfg-gate native_darwin to its lane`.
- [ ] **(e)** Dead post-refusal FIXED/DONTUNMAP code in the mremap handler (mremap-ruling review note): delete the provably-unreachable branches, keep the EOPNOTSUPP refusal + a comment pointing at the oracle report for when FIXED support is actually built. Tests unchanged (they pin the refusal). Commit: `chore(runtime): remove dead mremap FIXED/DONTUNMAP branches`.

Each item: both-platform verification before its commit (macOS clippy + targeted suites; box build + targeted suites).

---

### Task 5: Phase-2 gate + evidence

**Files:**
- Modify: `docs/native-lane-seam-phase1-evidence.md` → rename? NO — create `docs/native-lane-seam-phase2-evidence.md`.

- [ ] **Step 1:** macOS `just ci` (background, staged-log pattern); classify vs the known residue table — nothing new.
- [ ] **Step 2:** Box full suite + LTP gate; equivalence vs Task-3 baseline.
- [ ] **Step 3:** Metrics: `native_freebsd.rs` line count (target ≤16K from 19.7K), twin-fn count (expect ↓ as memory/cache twins collapse), `identity_memory` consumer count, shared-cache adoption boundary statement. Honest "what Phase 2 did NOT do" (loop merge, exec capsule, futex trait → Phase 3).
- [ ] **Step 4:** Commit — `docs(native): phase-2 seam evidence` → finishing-a-development-branch.

---

## Phase 3 pointer (separate plan)

(a) The loop merge (`run_native_dsr_thread_loop_profiled` × `run_x86_thread` behind `NativeLane`) — now standing on shared memory+cache; (b) FreeBSD adoption of `native_exec_capsule` + `prepared_image` (deleting `parse_loadable_elf`/`load_static_pie` duplication); (c) cross-process futex host trait (umtx + waiter-table vs `__ulock`); (d) NetBSD lane bring-up as the seam acceptance test (host glue: jit dual-map analog, fault shim, `SYS___futex`, identity-memory reuse) — per the maintainer's roadmap, after stable state.
