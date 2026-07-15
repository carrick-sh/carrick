# Native Memory-Lock Retirement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove contention on the process-wide `Arc<parking_lot::Mutex<NativeMappedMemory>>` (measured at ~70% of all host syscalls under a multithreaded guest) by making the read-mostly guest-memory metadata concurrently readable, moving the exclusive monitor to its own fine-grained lock, and extracting the type into a focused module.

**Architecture:** Convert the single big `Mutex` to an `RwLock` where the hot syscall/trap path takes `.read()` and only the mapping mutators (mmap/munmap/mprotect/madvise/brk/exec + fault-commit protect) take `.write()`. Correctness is **compiler-enforced**: a `.read()` guard yields `&NativeMappedMemory`, so any method that still needs `&mut self` cannot compile under a read guard. The one thing blocking the hot path from being `&self` today — `write_bytes_raw` mutating the embedded exclusive monitor — is removed first (Phase 1) by giving the exclusive-sequence map interior mutability and folding the struct reservation into the already-per-thread `NativeThreadRuntime`.

**Tech Stack:** Rust, `parking_lot::{Mutex, RwLock}`, `crates/carrick-runtime/src/native_darwin.rs` (+ a new `native_darwin/mapped_memory.rs` module in Phase 3), the native probe gate, `scripts/dtrace/syscall-amplification.d`, the frozen 1M-trap Go W1 measurement command.

**Reference documents (read before starting):**
- Design spec: `docs/superpowers/specs/2026-07-14-native-memory-lock-retirement-design.md`
- Lock-site read/write classification (the authoritative per-site map): `.superpowers/sdd/memlock-classification.md`
- Confirmed root cause + method: `.superpowers/sdd/condvar-pin-confirmed.md`

## Global Constraints

- NEVER `git commit --no-verify`; the pre-commit hook runs `just fmt-check`. Every commit must pass `cargo fmt --all -- --check`.
- Rebuild + re-sign before ANY guest run: `just build` (macOS → `scripts/build-signed.sh`, production entitlements). An unsigned binary fails every guest run with HV_DENIED.
- Stamp every guest run with a unique `CARRICK_RUN_ID`; reap ONLY yours with `sudo -n scripts/sudo/kill.sh "$CARRICK_RUN_ID"`. Never a bare kill.
- Never overlap Carrick and Docker phases.
- Never weaken AArch64 exclusive or signal semantics; never raise `max_traps` or timeouts to pass a gate.
- Correctness beats coverage: a livelock, lost wakeup, or wrong value in the atomic/futex/threading stress gate STOPS the phase.
- Untraced signed runs are the ONLY wall/CPU authority; measure before/after on the frozen command (below).
- The measurement command (identical before/after; both hit the 1M-trap ceiling):
  ```
  target/release/carrick run --name "$CARRICK_RUN_ID" --max-traps 1000000 --raw --fs host \
    -w /usr/local/go/src/go/types --exec-backend native --native-page-profile native16k \
    localhost:5005/carrick-go-conformance:1.24 /conformance/go_types.test -test.v \
    -test.run '^TestImplicitsInfo$' -test.short
  ```

## Baseline invariants (all phases preserve)

- Blocking syscalls already run with NO memory lock held (guard dropped at native_darwin.rs:3449 before every `wait_native_*`). Preserve this.
- A metadata WRITE must exclude all readers (mmap cannot unmap a page mid-translation). Under `RwLock`, `.write()` guarantees this.
- Concurrent readers writing DIFFERENT guest addresses is sound; same-address is the guest's own race (Linux semantics).

## File Structure

- Phases 1–2: modify `crates/carrick-runtime/src/native_darwin.rs` in place (type alias :187, struct :6273, ~40 lock sites and the methods they call — all enumerated in the classification map).
- Phase 3: create `crates/carrick-runtime/src/native_darwin/mapped_memory.rs` and move `NativeMappedMemory` + its impls + the exclusive-monitor and config types there; `native_darwin.rs` keeps the dispatch/trap loop. (native_darwin is already a module dir — `native_darwin/dsr/` exists.)

---

## PHASE 1 — Move the exclusive monitor out of `NativeMappedMemory`

Goal: make every guest-RAM write (`write_bytes_raw`) stop mutating `NativeMappedMemory` struct fields, so those methods can become `&self`. No memory-lock type change yet. This is the prerequisite for Phase 2.

### Task 1: Give `exclusive_sequences` interior mutability

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin.rs` (struct field :6286; methods `invalidate_exclusive_range` ~:7748, `exclusive_load`/`exclusive_store` ~:7907/:7964, the CAS bump ~:8044, and any reader of the sequence map ~:7952)
- Test: inline `#[cfg(test)]` in `native_darwin.rs`

**Interfaces:**
- Produces: `exclusive_sequences: parking_lot::Mutex<BTreeMap<NativeExclusiveLocation, NativeExclusiveSequence>>` (was a bare `BTreeMap`). All accessors lock internally and take `&self`.
- Consumes: nothing new.

- [ ] **Step 1: Write the failing test.** Add a unit test asserting the invalidation-through-`&self` contract you are about to enable: constructing a `NativeMappedMemory` (use the existing test constructor — grep the test module ~:9774 for `biased_test_memory`/`native_test_memory`), take a shared `&memory`, and drive an exclusive load → overlapping write → verify a later exclusive store fails (reservation invalidated). Write it to call the methods with `&self` (it will not compile yet — they are `&mut self`).

```rust
#[test]
fn exclusive_invalidation_works_through_shared_ref() {
    // build a small test memory (see existing biased_test_memory helper)
    let memory = /* existing test constructor */;
    let m: &NativeMappedMemory = &memory;              // SHARED ref
    // record an exclusive reservation at an address via the &self path,
    // then a plain write overlapping it via &self, then assert a store CAS fails.
    // (Use the same helpers the existing exclusive tests use, but through &self.)
}
```

- [ ] **Step 2: Run it, verify it fails to COMPILE** (`exclusive_*` take `&mut self`):

Run: `cargo test -p carrick-runtime --lib exclusive_invalidation_works_through_shared_ref 2>&1 | head -30`
Expected: compile error `cannot borrow ... as mutable` / `&mut self` mismatch.

- [ ] **Step 3: Implement.** Change the field to `exclusive_sequences: parking_lot::Mutex<BTreeMap<NativeExclusiveLocation, NativeExclusiveSequence>>`. Update its constructor site(s) to `parking_lot::Mutex::new(BTreeMap::new())`. Change `invalidate_exclusive_range`, the sequence read on load, and the CAS bump to `&self` and lock the inner `Mutex` for the map access only. Keep the critical section minimal (lock, mutate/read the map, unlock). Do NOT change the struct `exclusive_reservation` field yet (Task 2).

- [ ] **Step 4: Run the test + full lib suite:**

Run: `cargo test -p carrick-runtime --lib -- --test-threads=1 2>&1 | tail -15`
Expected: the new test PASSES; 0 failures overall.

- [ ] **Step 5: Lint + commit:**

```bash
cargo clippy -p carrick-runtime --lib -- -D warnings && just fmt-check
git add -A && git commit -m "refactor(native): give exclusive_sequences interior mutability"
```
(Commit trailer: the standard Co-Authored-By + Claude-Session lines.)

### Task 2: Fold the struct `exclusive_reservation` into per-thread state

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin.rs` (struct field :6285; `exclusive_load`/`exclusive_store` :7907/:7964; the single-threaded-gated linux4k callers :5997/:6015; `NativeThreadRuntime.exclusive_reservation` already exists :2735)
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Produces: `NativeMappedMemory` no longer has an `exclusive_reservation` field. The linux4k guarded exclusive path threads `&mut thread_runtime.exclusive_reservation` (the already-per-thread field) into `exclusive_load`/`exclusive_store`, exactly as the DSR-hot path already does at :1789.
- Consumes: `NativeThreadRuntime.exclusive_reservation` (existing, :2735).

- [ ] **Step 1: Write the failing test.** A linux4k-path exclusive load/store round-trip that passes an explicit per-thread reservation and asserts the struct no longer owns one (the test will not compile until the field is removed and signatures updated). Model it on the existing exclusive tests (~:9900 `emulate subword exclusive load/store`).

- [ ] **Step 2: Run it, verify it fails** (field still exists / signature mismatch).

Run: `cargo test -p carrick-runtime --lib exclusive_ 2>&1 | head -30`
Expected: compile error referencing the removed field / changed signature.

- [ ] **Step 3: Implement.** Remove the `exclusive_reservation` field from `NativeMappedMemory`. Change `exclusive_load`/`exclusive_store` to take `reservation: &mut Option<NativeExclusiveReservation>` (matching `exclusive_load_for`/`exclusive_store_for` already at :7919/:7977). Update the linux4k callers (:5997/:6015 in `emulate_linux4k_guarded_*`) to pass the thread runtime's reservation. Since the linux4k guarded path is `live_threads > 1`-gated single-threaded (:2597), threading the per-thread reservation there is safe.

- [ ] **Step 4: Run tests:**

Run: `cargo test -p carrick-runtime --lib -- --test-threads=1 2>&1 | tail -15`
Expected: 0 failures.

- [ ] **Step 5: Commit** (`refactor(native): fold struct exclusive reservation into per-thread state`).

### Task 3: Make `write_bytes_raw` and the trap RAM-write path `&self`

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin.rs` (`write_bytes_raw` :8856 and its `&mut self` callers that only write guest RAM: `write_bytes`/`write_bytes_unchecked`/`zero_backing`; `NativeSignalTrap` :3168 and its `GuestMemory` impl :3193). Note `note_dsr_code_mutation` (:6586) is already `&self`.
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Produces: `write_bytes_raw(&self, ...)` (was `&mut self`). The only remaining metadata write inside it — `prepare_native16k_write_exec_host_write` for writes to an EXECUTABLE page — is split out: `write_bytes_raw` returns/flags "this write hit an exec page" so the caller can perform the metadata update under a write path (Phase 2 handles the escalation; in Phase 1 keep behavior identical by having `write_bytes` take `&mut self` ONLY on the exec-page branch, or route the exec-page metadata update through a small `&self` interior-mutable helper if one already fits). Prefer: `write_bytes_raw(&self)` for the common (non-exec) case; a separate `&mut self` `write_exec_page_bytes` for the SMC case, chosen by the existing `range_may_execute` check.
- Consumes: interior-mutable `exclusive_sequences` (Task 1), `dsr_generations` (already `&self`).

- [ ] **Step 1: Write the failing test.** Write bytes to a normal (non-exec) guest page through a SHARED `&NativeMappedMemory`, read them back, and assert success — plus assert an overlapping exclusive reservation is invalidated (through `&self`). Will not compile while `write_bytes_raw` is `&mut self`.

- [ ] **Step 2: Run it, verify it fails** (borrow/`&mut self`).

Run: `cargo test -p carrick-runtime --lib write_bytes_through_shared_ref 2>&1 | head -30`
Expected: compile error.

- [ ] **Step 3: Implement.** Change `write_bytes_raw` to `&self` for the non-exec path (guest-RAM write through the region host pointer + `invalidate_exclusive_range` via Task 1's interior lock + `note_dsr_code_mutation` via its existing `&self`). Split the exec-page metadata update (`prepare_native16k_write_exec_host_write`, which mutates `native_write_exec_writable_pages`/`native_page_protections`) into a `&mut self` path taken only when `range_may_execute` is true. Update `NativeSignalTrap`'s `GuestMemory::write_bytes_raw` impl (:3202) accordingly. Keep observable behavior byte-identical.

- [ ] **Step 4: Run tests + build the fusion gate binary:**

Run: `cargo test -p carrick-runtime --lib -- --test-threads=1 2>&1 | tail -15`
Expected: 0 failures.

- [ ] **Step 5: Commit** (`refactor(native): make guest-RAM write path take &self`).

### Task 4: Phase 1 correctness gate (no lock-type change yet)

**Files:** none (verification only).

- [ ] **Step 1: Build signed.**

Run: `just build 2>&1 | tail -2`
Expected: `built + signed: target/release/carrick`.

- [ ] **Step 2: Native probe gate.** Build probes if needed (`scripts/build-probes.sh`), then run the complete native gate:

Run: `just conformance-probes 2>&1 | tail -20`
Expected: no NEW failures vs the pre-Phase-1 baseline (the six known post-fork pthread-guard gaps — `exitgroupthreads`, `futexforkwakegroups`, `mtsigrelease`, `procladder_epollmgr`, `procladder_mixed`, `procladder_mt` — remain; nothing else regresses).

- [ ] **Step 3: Atomic/futex/threading stress gate.** Run the CAS/futex/thread probes ≥10x each under the native16k backend (where exclusive fusion is active). `scripts/run-probe.sh <name>` runs one probe under carrick AND Docker and diffs (prints `MATCH <name>` on success):

Run:
```bash
export CARRICK_NATIVE_PAGE_PROFILE=native16k CARRICK_EXEC_BACKEND=native
pass=0; fail=0
for p in futexpingpong futexwakeexact futexwakecount futexpilock futexprivatewakeexact futexrequeue manythreads forkexecpthread execthreads exitgroupthreads; do
  for i in $(seq 1 10); do
    out=$(CARRICK_RUN_ID="p1-$p-$i" timeout 120 scripts/run-probe.sh "$p" 2>/dev/null)
    echo "$out" | grep -q "^MATCH $p" && pass=$((pass+1)) || { fail=$((fail+1)); echo "NON-MATCH $p #$i"; }
  done
done
echo "PASS=$pass FAIL=$fail"
```
Expected: `FAIL=0` — every run MATCH; zero livelock/timeout/mismatch. (`exitgroupthreads` may hit the known post-fork pthread guard — if it was already NON-MATCH at the Phase-1 baseline, that is a pre-existing gap, not a regression; confirm against baseline.)

- [ ] **Step 4: `just ci` green.**

Run: `just ci 2>&1 | tail -5`
Expected: all stages pass.

- [ ] **Step 5: Commit any gate fixes** (only if a gate exposed a defect). Otherwise no commit.

---

## PHASE 2 — `Mutex<NativeMappedMemory>` → `RwLock<NativeMappedMemory>`

Goal: the contention win. With Task 3 done, the hot path methods are `&self`, so read guards compile; genuine mutators stay `&mut self` and require write guards. The compiler enforces the split.

### Task 5: Flip the lock type and let the compiler enumerate the sites

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin.rs` (type alias :187, instantiation :1277, and every `.lock()` site — the classification map lists all ~40 with R/W verdicts)

**Interfaces:**
- Produces: `type SharedNativeMemory = Arc<parking_lot::RwLock<NativeMappedMemory>>;`. Read sites call `.read()`, write sites `.write()`, the SMC write path `.upgradable_read()`.
- Consumes: Phase 1's `&self` write path.

- [ ] **Step 1: Change the type alias** to `Arc<parking_lot::RwLock<NativeMappedMemory>>` and the `:1277` instantiation to `parking_lot::RwLock::new(memory)`.

- [ ] **Step 2: Compile to get the site list.**

Run: `cargo build -p carrick-runtime 2>&1 | grep -E "no method named .lock.|error" | head -60`
Expected: an error at every `.lock()` site (RwLock has no `.lock()`). This IS the checklist.

- [ ] **Step 3: Convert each site per the classification map.** For each `.lock()`:
  - Rows marked **R** (address_mode, page-size, protections/regions reads, `dsr_process_translator`, fault reverse-translation, rejection predicates): `.read()`.
  - Rows marked **RAM** (complete_dsr_syscall :2484, deliver_dsr_pending_signal :2453, complete_dsr_sigreturn :2513, lower_dsr_fault signal inject :2643, native_dc_zva :1835, clone/fork tid writes :2923/:3064/:4574/:4577/:4629/:4634, select/sleep finalizers :3538/:3549/:3866): `.read()` — these now compile as `&self` after Phase 1.
  - Rows marked **W** (replace_image :2334, map_host_alias :2403, protect_range fault commits :2577/:2626, W^X fault :2586, linux4k guarded fault :2604): `.write()`.
  - The `:1588` `prepare_dsr_entry` conditional-W (SMC page prep): `.upgradable_read()`, upgrade to write only on the writable-W^X-page branch.
  - The `:3440` dispatch site (MIXED): pre-classify by syscall number — take `.write()` for the mapping mutators (mmap/munmap/mprotect/madvise/brk/exec — enumerate from `dispatch/mem.rs`), `.read()` otherwise. If any `.read()` choice fails to compile (a `&mut self` method is reached), that is the compiler catching a residual mutator: either it belongs on the write list (add it) or its receiver should be `&self` (Phase 1 missed it — fix the receiver, do NOT paper over with `.write()`).

- [ ] **Step 4: Build clean.**

Run: `cargo build -p carrick-runtime 2>&1 | tail -5`
Expected: builds with no errors.

- [ ] **Step 5: Full lib tests.**

Run: `cargo test -p carrick-runtime --lib -- --test-threads=1 2>&1 | tail -15`
Expected: 0 failures.

- [ ] **Step 6: Commit** (`perf(native): read-mostly RwLock for guest-memory metadata`).

### Task 6: Handle the `:3440` dispatch pre-classification cleanly

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin.rs` (`dispatch_native_syscall_inner` :3427–:3449)

**Interfaces:**
- Produces: a small `fn native_syscall_mutates_mappings(nr: u64) -> bool` (mmap/munmap/mprotect/madvise/mremap/brk/exec numbers) that selects `.write()` vs `.read()` at :3440. Keep it next to the call site with a comment pointing at the classification map.

- [ ] **Step 1: Write the failing test.** Unit-test `native_syscall_mutates_mappings`: returns true for the AArch64 numbers of mmap(222)/munmap(215)/mprotect(226)/madvise(233)/mremap(216)/brk(214)/execve(221)/execveat(281), false for read(63)/write(64)/futex(98)/getpid(172)/clock_gettime(113).

```rust
#[test]
fn mapping_mutators_take_write_guard() {
    for nr in [222u64, 215, 226, 233, 216, 214, 221, 281] {
        assert!(native_syscall_mutates_mappings(nr), "nr {nr} should be a mapping mutator");
    }
    for nr in [63u64, 64, 98, 172, 113] {
        assert!(!native_syscall_mutates_mappings(nr), "nr {nr} should not");
    }
}
```

- [ ] **Step 2: Run it, verify it fails** (function not defined).

Run: `cargo test -p carrick-runtime --lib mapping_mutators_take_write_guard 2>&1 | head -20`
Expected: FAIL — `native_syscall_mutates_mappings` not found.

- [ ] **Step 3: Implement** the function (verify each Linux AArch64 syscall number against `crate::linux_abi` constants — do NOT hardcode a wrong number) and use it at :3440 to pick the guard.

- [ ] **Step 4: Run tests.**

Run: `cargo test -p carrick-runtime --lib mapping_mutators_take_write_guard 2>&1 | tail -5`
Expected: PASS.

- [ ] **Step 5: Commit** (`perf(native): take a write guard only for mapping-mutating syscalls`).

### Task 7: Phase 2 correctness gate + MEASURE (the payoff)

**Files:** none until measurement; then append results to `docs/native-default-conformance-campaign.md`.

- [ ] **Step 1: Build signed** (`just build`).

- [ ] **Step 2: Native probe gate + atomic/futex/thread stress gate.** Run `just conformance-probes` (expect no new failures vs the Phase-1 baseline) AND the ≥10x-per-probe stress loop from Task 4 Step 3 (expect `FAIL=0`). A livelock/lost-wake/mismatch here means a writer was misclassified as a reader under a read guard — STOP and fix (do not weaken the gate).

- [ ] **Step 3: `just ci` green.**

- [ ] **Step 4: RE-MEASURE amplification.** With a unique `CARRICK_RUN_ID`, run `scripts/dtrace/syscall-amplification.d` via `carrick trace` on the frozen command (see the Global Constraints command block). Expected: the `psynch_cvwait`+`psynch_cvsignal` share collapses from ~70% toward a small fraction; total host syscalls drop substantially.

- [ ] **Step 5: RE-MEASURE untraced wall/CPU** (authority). `/usr/bin/time -l target/release/carrick run ...` (frozen command) before/after. Compare real/user/sys against the Phase-1 baseline (capture the baseline by building at the Phase-1 commit if not already recorded). Expected: real + sys CPU improve; no regression.

- [ ] **Step 6: Record honestly.** Append measured before/after to the campaign ledger. If psynch does NOT collapse, the classification/guard split is wrong — investigate (re-run `psynch-callers.d` to see the new dominant caller) before claiming a win.

- [ ] **Step 7: Commit** the ledger update (`docs(native): record RwLock contention-reduction measurement`).

---

## PHASE 3 — Extract module + lock-free immutable config

Goal: durability/traversal. Extract `NativeMappedMemory` out of the 15k-line file; make the immutable config lock-free.

### Task 8: Factor immutable config out of the write path

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin.rs` (struct :6273; `address_mode`/`host_page_size`/`linux_page_size` readers)

**Interfaces:**
- Produces: a `NativeMemoryConfig { address_mode, host_page_size, linux_page_size }` read without the RwLock (stored as an `Arc<NativeMemoryConfig>` beside the `RwLock`, or as `Copy` fields cached on the per-thread runtime at image-load/exec). `replace_image` swaps it under the write path (exec is a whole-process quiesce, so a plain swap is safe).

- [ ] **Step 1: Write the failing test.** Assert `address_mode()`/`host_page_size()`/`linux_page_size()` are reachable without acquiring the RwLock (e.g., via the `Arc<NativeMemoryConfig>` handle). Will not compile until the handle exists.

- [ ] **Step 2: Run it, verify it fails.**

Run: `cargo test -p carrick-runtime --lib immutable_config_reads_lock_free 2>&1 | head -20`
Expected: FAIL — accessor/handle not defined.

- [ ] **Step 3: Implement** the config handle; route hot-path reads of these three fields through it; keep `replace_image` swapping it under the write guard.

- [ ] **Step 4: Tests + `just ci`.**

Run: `cargo test -p carrick-runtime --lib -- --test-threads=1 2>&1 | tail -10`
Expected: 0 failures.

- [ ] **Step 5: Commit** (`perf(native): read immutable memory config without the RwLock`).

### Task 9: Extract `NativeMappedMemory` into `native_darwin/mapped_memory.rs`

**Files:**
- Create: `crates/carrick-runtime/src/native_darwin/mapped_memory.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs` (remove the moved items; add `mod mapped_memory; use mapped_memory::*;`)

**Interfaces:**
- Produces: `mapped_memory` module exporting `NativeMappedMemory`, `SharedNativeMemory`, `NativeMemoryConfig`, the exclusive-monitor types, and the mapping/protection helpers. No behavior change.

- [ ] **Step 1: Move** the `NativeMappedMemory` struct, its impls, `NativeMemoryConfig`, the exclusive-monitor types/methods, and the mapping/protection helper fns into the new file. Add `pub(crate)`/`pub(super)` visibility as needed. Add `mod mapped_memory;` to `native_darwin.rs`.

- [ ] **Step 2: Build.**

Run: `cargo build -p carrick-runtime 2>&1 | tail -5`
Expected: builds (fix visibility errors the compiler flags).

- [ ] **Step 3: Move the relevant `#[cfg(test)]` unit tests** alongside the code they cover into the new module. Run them.

Run: `cargo test -p carrick-runtime --lib -- --test-threads=1 2>&1 | tail -10`
Expected: same test count green as before the move.

- [ ] **Step 4: `just ci` green.**

- [ ] **Step 5: Commit** (`refactor(native): extract NativeMappedMemory into its own module`).

### Task 10: Final full gate + measurement confirmation

**Files:** none (verification); append final numbers to the campaign ledger.

- [ ] **Step 1: `just build` + full native probe gate + fusion gate ≥10x + `just ci`.** Expected: all green, no regression vs Phase 2.

- [ ] **Step 2: Re-run the amplification + untraced wall/CPU measurement** (frozen command) to confirm Phase 3 introduced no regression vs Phase 2. Append to the ledger.

- [ ] **Step 3: Commit** the final ledger update (`docs(native): final memory-lock retirement measurement`).

---

## Self-review notes

- **Spec coverage:** Phase 1 (Tasks 1–4) = spec "move exclusive monitor out"; Phase 2 (Tasks 5–7) = spec "Mutex→RwLock" + the `:3440` pre-classification + measurement; Phase 3 (Tasks 8–9) = spec "extract module + lock-free immutable config"; Task 10 = final gate. The deferred seqlock alternative is intentionally not implemented.
- **Compiler-enforced safety** is the backbone: after Phase 1 makes receivers honest, a read guard cannot call a mutator. Task 5 Step 3 explicitly forbids papering over a compile error with `.write()` without first deciding whether the method is truly a mutator.
- **Measurement is mandatory** (Task 7) and honest-reporting is required if psynch does not collapse.
- **Every phase is independently landable and gated** by the atomic/futex/thread stress suite — the exact hazard class this refactor could break.
