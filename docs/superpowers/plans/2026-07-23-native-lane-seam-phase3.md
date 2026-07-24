# NativeLane Seam — Phase 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Merge the two per-lane thread run loops behind `NativeLane`, adopt the remaining shared POSIX modules on FreeBSD, factor cross-process futex behind a host seam, and bring up the NetBSD/x86_64 native lane as the acceptance test — completing the seam campaign.

**Architecture:** Final strangler stage on `native_freebsd.rs` (16.6K) + `native_darwin.rs` (13.0K) using the Phase-1/2 seams. The loop merge is the crux and is scouted before execution with a STOP gate. NetBSD bring-up is staged strictly behind pieces 1–3 gate-cleaning on FreeBSD.

**Tech Stack:** Rust 1.96.0 pinned; FreeBSD box (root@fbsd) as the proving lane; LTP gate `scripts/native-x86-ltp-gate.py`; NetBSD x86 host = willow VM 201 (verify availability) or fresh box.

**Design:** `docs/superpowers/specs/2026-07-23-native-lane-phase3-design.md` (approved). Prior evidence: `docs/native-lane-seam-phase2-evidence.md`.

## Global Constraints

- Behavior-preserving unless a task names its sanctioned change; behavior-adjacent tasks show LTP-gate pass-set equivalence (FreeBSD box before/after programmatic diff — the Phase-1/2 protocol).
- No scattered `#[cfg(target_os)]` in shared code; one cfg pair at the wiring point (NetBSD becomes a third `HostNativeLane` arm only in Task 5).
- `GuestIsa` grows sized-to-consumption; no speculative trait surface.
- Clean-room (man-pages/spec/oracle only; the mremap oracle pattern is the template for any NetBSD ABI question).
- Both platforms green per task before commit; box leg before every commit touching FreeBSD-compiled code; restore box branch after; STOP/BLOCKED if box dirty. Known residue: the §3 flake cluster (stash/baseline-prove, don't chase).
- Logical commit per task, standard trailers (`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` + session `Claude-Session:`), NEVER `--no-verify`.
- Branch: `feat/native-lane-seam-phase3` off main ≥ 7c3ea4af.

## Task 0: Repo hygiene (one small commit, first)

**Files:** remove `last_1000_commits.txt`, `.codex/` if it's scratch (verify it's not intentional tooling first — check for a hooks reference; the no-eprintln hook may be intentional — if so KEEP .codex, only remove last_1000_commits.txt).

- [ ] Verify `.codex/hooks/no-eprintln.sh` isn't wired into anything the repo needs (grep for it; if it's a live pre-commit/codex hook the maintainer uses, keep it). Remove `last_1000_commits.txt` (clearly a scratch artifact swept in during Phase 2). `git rm`, commit `chore(repo): remove scratch artifact swept into phase-2`.

## Task 1: Loop-merge precision map (read-only scouting → committed notes)

**Files:** Create `docs/superpowers/specs/2026-07-24-loop-merge-precision-map.md`. No code.

The two loops: `native_darwin.rs::run_native_dsr_thread_loop_profiled` (~855 ln) and `native_freebsd.rs::run_x86_thread` (~1,750 ln). Re-derive both fresh (post-Phase-2 line shifts).

- [ ] **Step 1:** Structural diff of the two loops: for each control-flow region (fetch→translate→cache-lookup→gateway-enter→exit-dispatch: Kicked/Signal/Syscall/Indirect/Sensitive→fault-lowering→signal-delivery→fork/exec handling), disposition: SHARED (identical shape, host/ISA calls differ → behind trait), DIVERGED (different structure → lane-specific callback), or LANE-ONLY (e.g. x86 xstate-residency policy, aarch64 exclusive-monitor — stays).
- [ ] **Step 2:** The `GuestIsa` growth surface: enumerate EXACTLY what a generic loop must call on the ISA (decode/classify + inst length, gateway entry/exit symbols, Context repr(C) accessors, sensitive catalog, counter plan) — proposed method signatures, sized to what the loop actually consumes. Cross-check both `carrick-dsr-aarch64` and `carrick-dsr-x86` already expose equivalent functions (they do, per Phase-1 maps) so the trait is a thin re-front, not new impl.
- [ ] **Step 3:** The DANGER ZONES — fault lowering (`lower_dsr_fault` vs `deliver_synchronous_x86_fault`) and xstate (x86 XSAVE/XRSTOR service vs aarch64 FP snapshot): characterize whether these can sit behind trait callbacks without semantic entanglement, or must stay lane-specific with the shared loop calling out. Be concrete: a wrong call here corrupts signal delivery or FP state.
- [ ] **Step 4: STOP ASSESSMENT** — is a genuine merge (meaningful shared body) achievable, or does the honest outcome tell us the loops share too little to justify the risk? If the latter, SAY SO — the controller escalates and Phase 3 may reshape Task 2 to a thinner skeleton or skip the loop merge. Commit the notes: `docs(native): loop-merge precision map`.

## Task 2: Extract the x86 translate/cache/chain engine into carrick-dsr-x86 (REDIRECTED)

**Redirect (2026-07-24, maintainer-approved on the Task-1 SKIP verdict):** The loop
merge is SKIPPED — the two loops share only ~10% and the gap is an *asymmetry*, not
ISA semantics: aarch64's translate/cache/JIT orchestration already lives in
`carrick-dsr-aarch64::translator` (2,643 ln) while x86's equivalent (~543 ln:
`run_x86_thread`'s block-plan → emit → JIT-cache → chain-edge orchestration, the
`CachedBlock`/`VaHasher` index, `PublishedFaultEntry`/`PendingChainEdge`) is still
inline in `native_freebsd.rs`. This task removes that asymmetry — the higher-leverage,
lower-risk move (an extraction like Phase-2 identity_memory, not a cross-ISA merge) —
and it serves NetBSD directly (NetBSD reuses the extracted engine, not inline code).

**Files:** new `crates/carrick-dsr-x86/src/translator.rs` (mirror the aarch64 translator's
shape as the target), `native_freebsd.rs` (delete the moved orchestration, call the
extracted engine), tests move with the code.

**Boundaries (from Phase-2 Task-3, HONOR):** the unaligned target-first chain-edge patch
protocol (`patch_slot`/`publish_guarded_chain_edge`) was KEPT lane-local because it's
incompatible with the shared aligned-atomic contract — decide during Step 1 whether it
moves into `carrick-dsr-x86::translator` (it can, since that crate is x86-specific and
per-thread-private — the shared-cache incompatibility was about `carrick-dsr`'s
`ConcurrentPublicationIndex`, not the x86 crate) or stays. The bump-allocator adoption
(TranslationCache::from_region) stays as-is.

- [ ] **Step 1 (INVENTORY + STOP GATE):** Map the x86 engine closure in `native_freebsd.rs`
  (run_x86_thread's translate/cache/chain regions + CachedBlock/VaHasher/PublishedFaultEntry/
  PendingChainEdge/patch_slot/publish_guarded_chain_edge + the SharedRun slice accounting it
  touches). For each: MOVE / STAY, mapped against the aarch64 translator's shape. Identify
  couplings that resist extraction (SharedRun, identity_memory, the run-loop's own signal/
  fault handling — those STAY in the loop; only the translate/cache/chain ENGINE moves). If a
  coupling can't be cleanly severed (as ExecutableEpoch was for identity_memory — needed a
  trait), design the minimal seam OR STOP and report. Also capture the box baseline
  (native_freebsd_x86 suite + LTP pass-set).
- [ ] **Step 2:** Extract per the inventory. aarch64 translator is the target shape (a
  `X86ProcessTranslator`/`X86ThreadTranslator` or equivalent). Move bodies verbatim (use-path
  edits only); color-moved evidence in the report.
- [ ] **Step 3:** macOS `cargo test -p carrick-dsr-x86 --lib` + `cargo test -p carrick-runtime --lib dsr` (aarch64 untouched pin — the aarch64 translator must be byte-unaffected); clippy. FreeBSD box: full native_freebsd_x86 suite + LTP == baseline (programmatic diff). == baseline or STOP.
- [ ] **Step 4:** Metrics: native_freebsd.rs delta; carrick-dsr-x86 growth; the x86/aarch64 crate-structure symmetry now achieved. Commit `refactor(dsr-x86): extract the x86 translate/cache engine (mirror aarch64)`. (Box wip-commits OK; squash to one.)

## Task 3: FreeBSD loader adopts carrick_mem::AddressSpace (RE-SCOPED)

**CORRECTION (2026-07-24):** The original Task 3 ("adopt exec-capsule + prepared_image")
was a CATEGORY ERROR in this plan and the design spec, caught by the Task-3 scout and
verified: `native_prepared_image::prepare` + `native_exec_capsule` are the DARWIN execve
*self-reexec transport* (hard-gated `cfg(macos,aarch64)`), NOT a shared ELF loader —
`native_freebsd.rs` never duplicated them (0 refs). The REAL dedup, maintainer-approved
on the scout's finding: FreeBSD's loader hand-rolls ELF loading (`Elf::parse` +
`map_one_elf` + hand-mmap in `parse_loadable_elf`/`load_static_pie`/`map_one_elf`),
while Darwin uses the shared `carrick_mem::AddressSpace` API
(`load_elf_bytes_with_reader_at_pie_base_without_runtime_regions` + `with_native_vdso` +
`with_linux_initial_stack_page_size` — native_darwin.rs:663/681/740/875). Make FreeBSD
adopt AddressSpace, deleting `map_one_elf` and the hand-rolled loading.

**Files:** `native_freebsd.rs` (`parse_loadable_elf`/`load_static_pie`/`map_one_elf`/
`load_execve_image` → `AddressSpace::load_elf_bytes...` + `with_native_vdso` +
`with_linux_initial_stack*`, mirroring native_darwin.rs's usage), delete the hand-rolled
loader.

**Behavior-adjacent — the risk:** the guest's initial stack/auxv/vDSO/vvar layout and the
PIE base must be BYTE-identical after adoption (a shifted auxv or stack breaks the guest
silently). LTP-equivalence is the guard; the initial-stack/entry-state must match exactly.

- [ ] **Step 1 (SCOUT + STOP GATE):** Inventory FreeBSD's hand-rolled loader
  (`map_one_elf`/`load_static_pie`/`parse_loadable_elf`/`build_initial_stack`) vs the
  AddressSpace API Darwin uses. Confirm x86-vs-aarch64 differences (R_X86_64_RELATIVE
  relocs, x86 vDSO/vvar/sigreturn-trampoline, identity-mapping model) are all expressible
  through the SHARED AddressSpace API (which already serves x86 elsewhere? check
  native_freebsd.rs:10371's `with_linux_initial_stack` use). If AddressSpace can't express
  a FreeBSD-x86-specific loader step without an aarch64-affecting change → STOP/BLOCKED with
  the specific step. Small additive AddressSpace extension is OK only with aarch64-unaffected
  proof. Capture box baseline (native_freebsd_x86 suite + LTP).
- [ ] **Step 2:** Adopt per the scout; iterate on box (native_freebsd.rs box-only compile).
- [ ] **Step 3:** macOS `cargo test -p carrick-runtime --lib` (+ `--lib dsr` aarch64 pin if
  AddressSpace/carrick-mem touched — identical) + clippy; FreeBSD box full suite + LTP ==
  baseline (programmatic diff — a stack/auxv shift shows here). Box leg before commit; restore
  box; STOP/BLOCKED if box dirty.
- [ ] **Step 4:** Metrics: native_freebsd.rs delta (deleting map_one_elf + hand-rolled load).
  Commit `refactor(runtime): freebsd loader adopts carrick_mem::AddressSpace`. (Box wip OK; squash to one.)

## Task 4: Cross-process futex host seam

**Files:** `crates/carrick-dsr/src/host.rs` or `lane.rs` (new `NativeHost` futex surface: wait/wake/requeue over an opaque key), `carrick-native-freebsd` (umtx + waiter-table body), `carrick-native-darwin` (`__ulock` body), `native_freebsd.rs`/`native_darwin.rs` (call the seam). Sized to what both lanes' futex paths actually need — the waiter-table workaround (FreeBSD's no-woken-count/no-atomic-requeue) may need to stay lane-side; scout that boundary and document it.

- [ ] Baseline. Factor the seam; each lane implements its primitive. macOS + box green; LTP == baseline (futex-heavy LTP cases are the real proof — ensure the gate list includes them). Commit `refactor(dsr): cross-process futex behind the NativeHost seam`.

## Task 5: NetBSD/x86_64 native lane bring-up (the acceptance test)

**PREREQUISITE (Step 0, may be its own commit):** NetBSD x86 toolchain + host. Verify willow VM 201 (x86_64 NetBSD, rustup 1.96 per [[project_netbsd_nvmm_backend]]) is reachable and has libclang (bindgen prereq); if not, STOP → BLOCKED on infra (maintainer decision). Pieces 1–4 MUST be merged + FreeBSD-gate-clean before this task starts.

**Files:** new `crates/carrick-native-netbsd/` (NativeHost impl: JIT — scout the fork-repair analog since NetBSD lacks SHM_ANON; fault shim over NetBSD mcontext_t; futex via SYS___futex per Task-4 seam; waiter-key via MAP_TRYFIXED semantics), `native/mod.rs` (NetBSD as third `HostNativeLane` arm), `page_profile.rs` (NetBSD/x86_64 capability-table entry), `carrick-portable` NetBSD arms (already partly done, ea72e207).

- [ ] **Step 1:** Scout the NetBSD JIT fork-repair analog (no SHM_ANON) — decide the mechanism (named shm+unlink vs MAP_PRIVATE CoW) and document before building.
- [ ] **Step 2:** Build the host crate + wiring; reuse carrick-dsr-x86 + identity_memory verbatim (the whole point — if either needs NetBSD-specific changes, that's a seam gap to escalate, not patch locally).
- [ ] **Step 3:** ACCEPTANCE — a static x86_64 hello ELF runs under `--exec-backend native` on NetBSD x86; then the native gate ladder (adapt scripts/native-x86-ltp-gate.py to the NetBSD host). Record the pass-set; parity-minus-known-gaps is success (NetBSD is new — a red list is expected and IS the NetBSD worklist, like the aarch64-BSD stage1 red list).
- [ ] **Step 4:** Commit series (host crate / wiring / bring-up evidence). If BLOCKED on infra at Step 0, Phase 3 lands 1–4 as the complete sub-deliverable and NetBSD becomes its own follow-up plan.

## Task 6: Phase gate + evidence

- [ ] macOS `just ci` (staged log), classify vs known residue. FreeBSD box full suite + LTP == baseline. Metrics into `docs/native-lane-seam-phase3-evidence.md`: combined native_darwin+native_freebsd line count (the loop merge is the big collapse); twin-fn count (target: near-zero non-trivial twins remain); NetBSD lane status (bring-up evidence or infra-blocked note); honest "what remains" (Phase-4 / follow-ups). Commit `docs(native): phase-3 seam evidence` → finishing-a-development-branch.

## Phase 4 pointer

If the loop merge lands: the campaign's structural goal is met and Phase 4 is polish + the deferred follow-ups (register-symmetry, reset_after_fork_for_exec rename, 9-test move, Default hardening, Intel-mac cfg proxy) + whatever the NetBSD red list surfaces. If NetBSD was infra-blocked: NetBSD bring-up is Phase 4's headline.
