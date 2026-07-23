# NativeLane Seam — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the `NativeLane`/`GuestIsa`/`NativeHost` seam skeleton from the approved portability-seams spec, make the host crates symmetric (`carrick-native-darwin` finally exists), turn the dead fork-repair hook into an enforced contract, unify the two disjoint native wiring graphs behind the capability table, and dedupe the first shareable clusters — all as behavior-preserving slices, each green on both platforms.

**Architecture:** Strangler pattern against `native_darwin.rs` (5.9K real lines) and `native_freebsd.rs` (19.6K lines). Phase 1 builds the trait skeleton sized to what these slices actually consume (traits grow per slice — no big-bang trait design), extracts the mechanical host-crate and shared-module moves, and stops before the two big run loops. Phase 2 (separate plan, after Phase 1 validates the trait shape) merges the thread-loop/dispatch orchestration and moves `IdentityGuestMemory` to a neutral identity-memory module (the NetBSD-reuse play).

**Tech Stack:** Rust workspace (pinned 1.96.0), cc build for the C trap shim, existing conformance gates.

**Spec:** `docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md` (approved; §"What moves where", §crate graph, §fixed decisions). Structural ground truth for this plan came from a full mapping of both lane files (2026-07-23); key line refs are embedded per task.

## Prerequisites / branch policy

- Base this work on `main` AFTER the `feat/bsdvm-aarch64-lanes` branch merges (it owns `scripts/`+`justfile`; this plan owns `crates/`+`csrc/` — overlap is zero, but the build-health commit `535f887a` on that branch is REQUIRED for macOS clippy/build to pass at all. Do not start from a main that predates it).
- FreeBSD verification host: `root@10.14.14.189` (git remote `fbsd` → `root@fbsd:/root/carrick`). Every command there needs `. ~/.cargo/env`. Push with `git push fbsd HEAD:refs/heads/<branch>` then ssh-checkout.

## Global Constraints

- **Behavior-preserving slices.** Every task is a pure move or a mechanically-equivalent refactor; any contract change (Task 4's fork-repair) is explicitly called out and test-pinned. "Byte-identical move" tasks must show `git diff --find-copies` evidence or old-vs-new file diff of moved bodies.
- **No scattered `#[cfg(target_os/target_arch)]` in shared native code** (spec fixed decision: "review-rejectable smell"). Exactly one cfg pair selects `HostNativeLane` at the wiring point.
- **Both platforms green per task, before its commit:** macOS: `just fmt-check && just clippy && cargo test -p <touched crates>`; FreeBSD box: `cargo build -p carrick-runtime && cargo test -p carrick-runtime --test native_freebsd_x86` (plus crate tests for touched crates). Loader/exec-touching tasks additionally run the on-box LTP gate subset (Task command given inline).
- **Process-global invariants stay:** `RUN_LOCK` (one native run per process), fixed-address arenas, `IDENTITY_*` statics are shared constraints, NOT lane parameters — do not attempt to parameterize them in Phase 1 (mapping: native_freebsd.rs:10441, 1846-1853, coupling-hazards section).
- **Clean-room:** ABI knowledge from man-pages/specs only; never Linux kernel/UAPI/glibc source.
- Commit per task (logical commits), conventional subject given per task, ending with:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` + the session `Claude-Session:` trailer line. NEVER `--no-verify`.
- Test suites referenced: macOS runtime lib tests include the JIT-entangled DSR suites under `native_darwin/dsr/*` (7K test lines) — they must keep linking after every move.

## File Structure (Phase 1 end-state)

- `crates/carrick-dsr/src/lane.rs` — NEW: `GuestIsa`, `NativeHost`, `NativeLane` traits (Phase-1-sized).
- `crates/carrick-dsr/src/host.rs` — MODIFIED: `NativeHostJit` gains `remap_for_fork_child`; fork-repair contract documented.
- `crates/carrick-native-darwin/` — NEW crate: `csrc/native_darwin.c` (byte-identical move), `build.rs` (cc), `DarwinHostJit` (moved from `native_darwin/darwin_jit.rs`), `DarwinHost` (NativeHost impl).
- `crates/carrick-native-freebsd/src/` — MODIFIED: `FreebsdHost` (NativeHost impl), `jit.rs` fork-hazard doc rewritten to the enforced contract, `remap_for_fork_child` impl.
- `crates/carrick-dsr-aarch64/src/lib.rs` + `crates/carrick-dsr-x86/src/lib.rs` — MODIFIED: `Aarch64Isa` / `X8664Isa` marker impls.
- `crates/carrick-dsr/src/prepared_image.rs` — NEW HOME (pure move from `carrick-dsr-aarch64/src/prepared_image.rs`; aarch64 crate re-exports for compat).
- `crates/carrick-runtime/src/native/mod.rs` — NEW: `HostNativeLane` wiring point (the one cfg pair) + entry facade.
- `crates/carrick-runtime/src/native/fork_child.rs` — NEW: shared `native_after_fork_child` hook list (both lanes call it).
- `crates/carrick-runtime/src/{execute.rs,runtime.rs,lib.rs}` — MODIFIED: native entry calls route through `crate::native::` facade.
- Docs: spec drift fix, `AGENTS.md` §Native rewrite, README crate table.

---

### Task 1: `lane.rs` — Phase-1-sized seam traits + ISA markers

**Files:**
- Create: `crates/carrick-dsr/src/lane.rs`; Modify: `crates/carrick-dsr/src/lib.rs` (add `pub mod lane;`)
- Modify: `crates/carrick-dsr-aarch64/src/lib.rs`, `crates/carrick-dsr-x86/src/lib.rs` (ISA impls)
- Test: unit tests inside `lane.rs` + each ISA crate

**Interfaces (Produces):**
```rust
// carrick-dsr/src/lane.rs
/// Guest-ISA half of a native lane. Phase 1 carries only what the shared
/// slices consume; gateway/emit surfaces join in Phase 2 (spec §traits).
pub trait GuestIsa: 'static + Send + Sync {
    const NAME: &'static str;                 // "aarch64" | "x86_64"
    /// Exclusive end of canonical user VA (x86_64: 1<<47; aarch64: 1<<48).
    const USER_VA_END_EXCLUSIVE: u64;
    /// Native guest page size the ISA lane translates for.
    const GUEST_PAGE_SIZE: usize;
}

/// Host-OS half of a native lane. Phase 1: JIT authority only.
pub trait NativeHost: 'static + Send + Sync {
    const NAME: &'static str;                 // "darwin" | "freebsd"
    fn active_jit() -> &'static dyn crate::host::NativeHostJit;
}

/// A concrete (ISA, Host) pairing. Native lanes are same-ISA by definition.
pub trait NativeLane: 'static + Send + Sync {
    type Isa: GuestIsa;
    type Host: NativeHost;
}
```
ISA impls: `pub struct Aarch64Isa;` in `carrick-dsr-aarch64` (`NAME="aarch64"`, `USER_VA_END_EXCLUSIVE = 1<<48`, `GUEST_PAGE_SIZE = 16384` — Darwin lane value today; revisit when a 4K aarch64 host lane exists) and `pub struct X8664Isa;` in `carrick-dsr-x86` (`NAME="x86_64"`, `USER_VA_END_EXCLUSIVE = 1<<47` — must equal `native_freebsd.rs`'s `X86_64_USER_END_EXCLUSIVE` (line ~344 region), `GUEST_PAGE_SIZE = 4096`).

- [ ] **Step 1: Failing tests** — in each ISA crate, a test asserting the impl's constants (e.g. `assert_eq!(X8664Isa::USER_VA_END_EXCLUSIVE, 1u64<<47)`), and in `lane.rs` a compile-check test with dummy lane types proving the trait bundle composes (`struct TestLane; impl NativeLane for TestLane { ... }`) using a `fn assert_lane<L: NativeLane>()` helper. Run `cargo test -p carrick-dsr -p carrick-dsr-aarch64 -p carrick-dsr-x86` — FAIL (unresolved `lane`).
- [ ] **Step 2: Implement** the code above verbatim; `NativeHost` has no impls yet (Tasks 2–3 provide them) — the lane.rs test uses a local dummy Host impl returning `unimplemented!()`-free `UnsupportedHostJit`-style stub (copy the fail-closed pattern from `native_darwin/darwin_jit.rs`'s `unsupported` module).
- [ ] **Step 3: Green** on the same three crates; then macOS `just clippy`.
- [ ] **Step 4: Cross-check the constant against the consumer:** `grep -n "X86_64_USER_END_EXCLUSIVE" crates/carrick-runtime/src/native_freebsd.rs` and add a runtime-crate test `assert_eq!(carrick_dsr_x86::X8664Isa::USER_VA_END_EXCLUSIVE, <the module's const>)` so the two cannot drift until Phase 2 deletes the local one.
- [ ] **Step 5: Commit** — `feat(dsr): NativeLane/GuestIsa/NativeHost seam traits (phase 1)`

---

### Task 2: `carrick-native-darwin` — host crate symmetry (byte-identical moves)

**Files:**
- Create: `crates/carrick-native-darwin/{Cargo.toml,build.rs,src/lib.rs,src/jit.rs}`, `crates/carrick-native-darwin/csrc/native_darwin.c` (MOVE of `crates/carrick-runtime/csrc/native_darwin.c` — verify current path with `fd native_darwin.c`)
- Modify: `crates/carrick-runtime/Cargo.toml` (dep, macOS target-gated like `carrick-native-freebsd` is freebsd-gated — mirror that stanza), `crates/carrick-runtime/build.rs` (REMOVE the cc build of the moved C file), `crates/carrick-runtime/src/native_darwin/darwin_jit.rs` (becomes a re-export shim of the moved `DarwinHostJit`, exactly like the `dsr/*` shim convention)
- Test: existing macOS runtime suites are the pin (JIT-entangled tests must keep linking); new crate gets a `supported()`/`map_code_cache` smoke test.

**Interfaces (Produces):** `carrick_native_darwin::{DarwinHostJit, active_host_jit()}` (same signatures as the FreeBSD twin: `pub fn active_host_jit() -> &'static dyn carrick_dsr::host::NativeHostJit`), plus `pub struct DarwinHost;` implementing `carrick_dsr::lane::NativeHost` (Task 1) with `active_jit() = active_host_jit()`. Mirror `carrick-native-freebsd/src/lib.rs`'s crate-level `#![cfg(target_os = "macos")]` gating pattern.

- [ ] **Step 1:** Locate every extern symbol the runtime links from `native_darwin.c` (`grep -n 'extern "C"' crates/carrick-runtime/src/native_darwin.rs crates/carrick-runtime/src/native_darwin/*.rs` + the build.rs cc stanza). Record the list in the task report — the move must keep every symbol exported.
- [ ] **Step 2:** Create the crate; move the C file byte-identical (`git mv` so history follows); `build.rs` = the cc invocation copied from carrick-runtime's build.rs (same flags); move `DarwinHostJit` + the `unsupported` fallback from `darwin_jit.rs` into `src/jit.rs` unchanged; `darwin_jit.rs` becomes `pub(crate) use carrick_native_darwin::{...};` (keep the existing freebsd re-export arm it already carries).
- [ ] **Step 3:** Add `DarwinHost` impl (new code, ~10 lines). Add the smoke test.
- [ ] **Step 4:** macOS: `cargo build -p carrick-native-darwin && cargo test -p carrick-runtime` (full — the DSR oracle/gateway suites are the acceptance) + `just clippy`. Verify byte-identical: `git diff --find-renames --stat HEAD~0` shows the C file as a rename, not add+delete... (use `git log --follow` after commit to confirm).
- [ ] **Step 5:** FreeBSD box: push + `cargo build -p carrick-runtime` (proves the target-gating didn't leak).
- [ ] **Step 6: Commit** — `refactor(native): extract carrick-native-darwin host crate`

---

### Task 3: `FreebsdHost` + fork-repair contract (`remap_for_fork_child`)

**Files:**
- Modify: `crates/carrick-dsr/src/host.rs`, `crates/carrick-native-freebsd/src/{lib.rs,jit.rs}`, `crates/carrick-native-darwin/src/jit.rs`, `crates/carrick-runtime/src/native_freebsd.rs` (`fork_child_rebuild`, lines ~11365-11402)
- Test: `carrick-native-freebsd` unit test + existing `native_freebsd_x86.rs` fork tests on the box

**Interfaces (Produces):**
```rust
// carrick-dsr/src/host.rs — ADDITIVE to NativeHostJit:
/// Fork-repair contract. Called in the CHILD immediately after fork, before
/// any guest thread runs. `Inherited` = the child may keep executing from the
/// inherited region (private/CoW mapping). `Fresh` = the inherited region is
/// unsafe to share (e.g. MAP_SHARED dual-map: a child re-JIT would clobber
/// the parent's live code) and the child must adopt the returned region.
pub enum ForkChildJit { Inherited, Fresh(JitRegion) }
fn remap_for_fork_child(&self, prior: &JitRegion) -> std::io::Result<ForkChildJit>;
```
No default impl — every host answers explicitly. Darwin: `Ok(ForkChildJit::Inherited)` (MAP_JIT is MAP_PRIVATE; child gets CoW — cite the existing jit.rs doc contrast). FreeBSD: `Ok(ForkChildJit::Fresh(self.map_code_cache(prior.capacity)?))`. `after_fork_child` REMAINS (Darwin translators call it — verified consumers exist); its doc now says "in-place post-fork repair for lanes whose region survives fork; region REPLACEMENT is `remap_for_fork_child`".

- [ ] **Step 1: Failing test** in `carrick-native-freebsd`: `remap_for_fork_child` returns `Fresh` with a region of the same capacity and distinct `exec_base`. (Compile-fail first: method doesn't exist.)
- [ ] **Step 2:** Implement trait method + both impls + `FreebsdHost: NativeHost` (mirrors Task 2's `DarwinHost`).
- [ ] **Step 3:** Rewire `fork_child_rebuild`: replace the direct `parent.jit.map_code_cache(cache_len)` call with `match parent.jit.remap_for_fork_child(&parent.region)? { Fresh(r) => r, Inherited => <keep parent.region as today's Darwin-lane semantics would — on this lane treat as unreachable with a fail-closed error> }`. Preserve the fault-shim re-registration that follows (`fault::register_code_region`).
- [ ] **Step 4:** REWRITE `crates/carrick-native-freebsd/src/jit.rs:21-31`'s stale "Fork hazard (M1 item — documented, not yet closed) … Do not enable guest execution" block: the hazard is CLOSED and now ENFORCED by `remap_for_fork_child` (reference the review finding + `fork_child_rebuild`). This retires a standing review finding — say so in the commit body.
- [ ] **Step 5:** macOS green (`cargo test -p carrick-runtime -p carrick-dsr -p carrick-native-darwin`, clippy). FreeBSD box: `cargo test -p carrick-native-freebsd -p carrick-runtime --test native_freebsd_x86` — the fork/vfork suites (e.g. fork tests in `native_freebsd.rs`'s mod tests + `forkfpreclaim`-class integration tests) are the acceptance.
- [ ] **Step 6: Commit** — `feat(dsr): enforce fork-repair through the NativeHostJit seam`

---

### Task 4: One wiring point — `native/mod.rs` facade + graph unification (M0.8)

**Files:**
- Create: `crates/carrick-runtime/src/native/mod.rs`
- Modify: `crates/carrick-runtime/src/lib.rs` (mod decl at the `native_darwin`/`native_freebsd` decls, lines ~137-149; reroute `run_elf_native_dispatch*` lines ~893-917 and the `ExecutionBackend::Native` arm ~1781-1784), `crates/carrick-runtime/src/execute.rs` (arms at ~344, ~457), `crates/carrick-runtime/src/runtime.rs` (arm at ~296)
- Test: runtime lib tests + a new facade unit test

**Interfaces (Produces):**
```rust
// carrick-runtime/src/native/mod.rs
pub(crate) mod fork_child; // Task 5
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) type HostNativeLane = DarwinAarch64Lane;
#[cfg(all(target_os = "freebsd", target_arch = "x86_64"))]
pub(crate) type HostNativeLane = FreebsdX8664Lane;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct DarwinAarch64Lane;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl carrick_dsr::lane::NativeLane for DarwinAarch64Lane {
    type Isa = carrick_dsr_aarch64::Aarch64Isa;
    type Host = carrick_native_darwin::DarwinHost;
}
// (freebsd twin likewise)

// Entry facade — the ONLY place execute.rs/runtime.rs/lib.rs touch a lane:
pub(crate) fn run_oci_native(...same args execute.rs passes today...) -> ... {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return crate::native_darwin::run_elf_from_dispatcher_debug(...);
    #[cfg(all(target_os = "freebsd", target_arch = "x86_64"))]
    return Err(<typed Unsupported: "OCI native path pending phase 2 on this lane">);
    #[allow(unreachable_code)] { unreachable-fail-closed }
}
pub(crate) fn run_static_native(...) -> ...   // routes to native_darwin::run_static_elf | native_freebsd::run_static_x86_elf
pub(crate) fn run_dispatch_native(...) -> ... // routes today's lib.rs:917/1784 freebsd calls
```
This is honest strangling: the facade is where the two graphs MEET today, and Phase 2 replaces the per-lane `#[cfg]` bodies with `ProcessTranslator<HostNativeLane>`-style generic calls. The spec's "exactly one cfg pair" applies to lane SELECTION (`HostNativeLane`); the facade bodies keep their per-target arms until Phase 2 dissolves the two modules — document this in the module doc so nobody mistakes it for the end-state.

- [ ] **Step 1: Failing test:** a unit test asserting the facade exists and the wiring-point type resolves (`fn _assert() { let _ = core::marker::PhantomData::<HostNativeLane>; }` compile pin) — plus grep-based negative pins in the test: `execute.rs`/`runtime.rs`/`lib.rs` contain zero direct `native_darwin::`/`native_freebsd::` run-entry references after Step 2 (write the test with `include_str!` + assert on the sources — crude but effective drift guard; keep it).
- [ ] **Step 2:** Create the module; reroute ALL call sites named above through the facade. Behavior identical per target (pure indirection).
- [ ] **Step 3:** macOS full runtime tests + clippy; FreeBSD box: `cargo test -p carrick-runtime --test native_freebsd_x86` (34+ entry-point call sites exercise the rerouted path) + `examples/native_run.rs` still builds.
- [ ] **Step 4:** On-box LTP gate spot-check (entry path changed): `. ~/.cargo/env && python3 scripts/native-x86-ltp-gate.py --cases scripts/native-x86-ltp-cases.txt` (or the documented invocation in that script's header — read it first; run the standard case list; expected: same pass-set as the pre-task run — capture BOTH runs).
- [ ] **Step 5: Commit** — `refactor(runtime): single NativeLane wiring point + native entry facade`

---

### Task 5: Shared `fork_child.rs` — first orchestration dedup

**Files:**
- Create: `crates/carrick-runtime/src/native/fork_child.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs` (`native_after_fork_child`, ~line 5769), `crates/carrick-runtime/src/native_freebsd.rs` (`native_after_fork_child`, ~11415-11426)
- Test: both lanes' existing fork tests + a new unit test on the shared hook list

The two functions are near-copies (mapping: "FreeBSD is a strict subset/near-copy of Darwin's") calling the same ordered dispatcher hooks: `event_ring::reinit_after_fork`, `host_signal::reinit_after_fork`, output-buffer/fifo-beacon resets, `network_after_fork_child`, `epoll_after_fork_child`, `proc_after_fork_child`, `mem_after_fork_child`, `sysv_after_fork_child`.

- [ ] **Step 1:** Diff the two bodies (`git diff --no-index` on extracted snippets); record EVERY divergence in the report. If a divergence is semantic (not just Darwin having extra hooks), STOP and escalate with the diff — do not silently unify semantics.
- [ ] **Step 2: Failing test:** unit test asserting the shared function calls hooks in the documented order (inject a recording fake via a small `#[cfg(test)]` hook-override, or assert order by refactoring the list into a `const`-array-of-named-steps the test can read — prefer the latter: `pub(crate) fn after_fork_child_steps() -> &'static [(&'static str, fn(&SyscallDispatcher))]`).
- [ ] **Step 3:** Implement `native::fork_child::dispatcher_after_fork_child(d: &Arc<SyscallDispatcher>, <flags for the divergences found in Step 1>)`; both lanes' `native_after_fork_child` become one-line calls (keeping any lane-extra steps INLINE at their call site, explicitly commented as lane-specific).
- [ ] **Step 4:** macOS full runtime tests + clippy; FreeBSD box fork/vfork suites (same command as Task 3 Step 5).
- [ ] **Step 5: Commit** — `refactor(runtime): shared native fork-child dispatcher reset`

---

### Task 6: `prepared_image` → neutral ground (pure move)

**Files:**
- Move: `crates/carrick-dsr-aarch64/src/prepared_image.rs` → `crates/carrick-dsr/src/prepared_image.rs` (git mv)
- Modify: `crates/carrick-dsr-aarch64/src/lib.rs` (`pub use carrick_dsr::prepared_image;` compat re-export), `crates/carrick-dsr/src/lib.rs` (mod decl), `crates/carrick-dsr/Cargo.toml` if the module pulls deps the crate lacks (check its imports FIRST — if it imports aarch64-only types, STOP: report exactly which, and instead split only the ISA-free schema; do not force the move)
- Test: existing consumers (`carrick-runtime` `native_prepared_image.rs` shim at 14 lines, `native_exec_capsule.rs`, `lib.rs`) compile unchanged; dsr crate takes the module's unit tests with it.

Rationale: the spec's crate graph puts lane-shared content in `carrick-dsr`; `prepared_image` is documented "UNCONDITIONAL on purpose… compiles on every target" yet lives in the aarch64 crate, which structurally discourages the x86 lane from adopting it (it currently doesn't — zero references). Moving it is the precondition for Phase 2's "FreeBSD adopts prepared-image/exec-capsule" slice.

- [ ] **Step 1:** `grep -n "use crate::\|use carrick" crates/carrick-dsr-aarch64/src/prepared_image.rs` — inventory intra-crate deps. Proceed only if ISA-free (expected per its own doc); otherwise STOP per above.
- [ ] **Step 2:** git mv + wire mods + compat re-export. No body edits beyond `use` paths.
- [ ] **Step 3:** macOS `cargo test -p carrick-dsr -p carrick-dsr-aarch64 -p carrick-runtime` + clippy; FreeBSD box `cargo build -p carrick-runtime`.
- [ ] **Step 4: Commit** — `refactor(dsr): prepared_image to the neutral crate (pure move)`

---

### Task 7: Truth-up — spec drift, AGENTS.md, README

**Files:**
- Modify: `docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md` (append a dated "Implementation drift" subsection — do NOT rewrite approved history: SHM_ANON dual-map superseded mprotect-flip for `carrick-native-freebsd` (quote jit.rs's rationale); `carrick-native-darwin` now exists (Task 2); fork-repair contract shape (Task 3); facade-first M0.8 wiring (Task 4))
- Modify: `AGENTS.md` §"Native (DSR) backend" (~lines 108-112): rewrite to current reality — crate list (dsr, dsr-aarch64, dsr-x86, native-darwin, native-freebsd), the two lane files' current roles + line-scale, `HostNativeLane` wiring point, Phase-2 pointer. This retires review finding #4.
- Modify: `README.md` crate table (stale count; missing `carrick-dsr-x86`, `carrick-native-freebsd`, now `carrick-native-darwin`).

- [ ] **Step 1:** Write all three; every claim must be greppable-true at HEAD (the AGENTS.md rewrite especially — cite paths that exist).
- [ ] **Step 2:** `just fmt-check` (docs don't trigger fmt, but hook runs); commit — `docs(native): truth-up seam spec drift, AGENTS.md, README crates`

---

### Task 8: Phase-1 gate — cross-platform bless + duplication metric

**Files:** none (runs + one ledger doc)
- Create: `docs/native-lane-seam-phase1-evidence.md` (metrics + gate outputs)

- [ ] **Step 1:** macOS: `just ci` to completion (this is the first full-gate run after all moves). Expected green; if the pre-existing `carrick-dsr-x86` arm64-host test failure (`signal_xstate_roundtrip…` panics `Unavailable("non-x86 host")`) fires, record it as the KNOWN pre-existing item (fix is a host-arch gate on the test — do it here as a bonus one-liner if trivial: `#[cfg(target_arch = "x86_64")]` on the test fn, commit separately as `test(dsr-x86): gate cpuid-dependent test to x86 hosts`).
- [ ] **Step 2:** FreeBSD box: full `cargo test -p carrick-runtime` + the LTP gate case list; compare pass-set to the Task-4 baseline capture — must be identical.
- [ ] **Step 3:** Metrics into the evidence doc: same-name twin-fn count between the two lane files (baseline 43; expect ↓ by the Task-5 cluster), `native_freebsd.rs`/`native_darwin.rs` line counts, `grep -c "NativeLane" crates/ -r` (baseline 0 → now real), the facade's negative-pin greps.
- [ ] **Step 4: Commit** — `docs(native): phase-1 seam evidence` — then hand off to superpowers:finishing-a-development-branch.

---

## Phase 2 pointer (separate plan, NOT this one)

Ordered candidates, from the mapping: (a) `IdentityGuestMemory` + checked-copy + `NativeMapping` machinery (~2K lines) → neutral identity-memory module keyed on `GuestIsa` consts — the direct NetBSD-reuse play; (b) generic thread-loop/dispatch merge (`run_native_dsr_thread_loop_profiled` 855 lines vs `run_x86_thread` 1750 lines) behind `NativeLane`; (c) FreeBSD adoption of `prepared_image` + `native_exec_capsule` (replacing `parse_loadable_elf`/inline exec); (d) cross-process futex host trait (umtx vs `__ulock` + waiter-table); (e) `carrick_dsr::cache::TranslationCache` adoption by the x86 lane (replacing inline `CachedBlock`). Each carries the LTP-gate-equivalence acceptance used in Task 4/8.
