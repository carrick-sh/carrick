# Native Direct Exec Reservation Implementation Plan

> **Execution requirement:** Follow this plan with the
> `superpowers:test-driven-development` skill. The exact-allocation test must be
> observed red before changing the reservation implementation.

**Goal:** Reserve a vacant Darwin-native Direct exec interval at its exact
guest address without overwriting host mappings, so split dyld ranges no longer
crash Node or `ltp-eventfd01` during emulated exec.

**Architecture:** Replace the nonfixed hint `mmap` probe with
`mach_vm_allocate(..., VM_FLAGS_FIXED)` from the maintained `mach2` crate.
`VM_FLAGS_OVERWRITE` is never passed. A successful exact allocation is changed
to `VM_PROT_NONE` and retained by the existing RAII guard. `KERN_NO_SPACE`
falls through to the existing strict dyld delegated-empty classification; all
other Mach failures remain errors.

**Tech stack:** Rust 1.96, `mach2` 0.4.3, Darwin Mach VM, Carrick signed native
conformance harness.

**Controller design:**
[`docs/superpowers/specs/2026-07-13-native-default-conformance-quality-design.md`](../specs/2026-07-13-native-default-conformance-quality-design.md)

---

## Task 1: Reproduce the Node-sized split-range failure in a host test

**Files:**

- Modify: `crates/carrick-host/src/host_proc.rs`

- [ ] **Step 1: Add `fork_child_split_canonical_gap_is_reserved_exactly`.**

  In `direct_vm_reservation_tests`, use the existing outer `fork_test` helper.
  Inside it:

  1. map one writable sentinel page at `0x4_0000_0000` with the existing
     test-only `MAP_FIXED` setup;
  2. write a sentinel byte and fork a nested child;
  3. in the nested child, call
     `reserve_self_direct_vm_range(0x4_0002_4000, 0x0628_0000)`;
  4. require `DirectVmReservationOutcome::Reserved(guard)`, drop the guard,
     verify the source sentinel is unchanged, and exit zero;
  5. in the parent, reap and require the nested child to exit zero.

  The start, length, and end (`0x4_062a_4000`) reproduce the measured Node
  collision. The source page creates the split region shape. Do not accept
  `DelegatedDyldPmapEmpty`: the test proves ownership of the vacant tail.

- [ ] **Step 2: Run the focused test and observe RED.**

  ```bash
  cargo test -p carrick-host fork_child_split_canonical_gap_is_reserved_exactly -- --nocapture
  ```

  Expected RED: current nonfixed `mmap` redirects and the following single
  covering-region check returns `DirectVmReservationError::Redirected`.

- [ ] **Step 3: Stop if the failure shape differs.**

  If the current implementation returns `Reserved`, confirm the exact host
  macOS version and repeat the measured Node command before changing code. If
  it returns an occupied region rather than the split-range redirect, inspect
  that region with the existing Mach query helpers and update the test to the
  measured vacant tail. Never use `MAP_FIXED` as the production vacancy probe.

## Task 2: Add exact non-overwriting Mach allocation

**Files:**

- Modify: `Cargo.toml`
- Modify: `crates/carrick-host/Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `crates/carrick-host/src/host_proc.rs`

- [ ] **Step 1: Add the maintained Mach bindings dependency.**

  Add `mach2 = "0.4.3"` to `[workspace.dependencies]`. Add a macOS-only
  dependency in `crates/carrick-host/Cargo.toml`:

  ```toml
  [target.'cfg(target_os = "macos")'.dependencies]
  mach2.workspace = true
  ```

  Let Cargo update `Cargo.lock`. Do not add new raw `extern "C"` declarations.

- [ ] **Step 2: Replace the hint `mmap` first attempt.**

  In `reserve_self_direct_vm_range`, after checked range conversion:

  1. obtain `task` with `mach2::traps::mach_task_self()`;
  2. initialize `address` to the requested start;
  3. call `mach2::vm::mach_vm_allocate(task, &mut address, length,
     mach2::vm_statistics::VM_FLAGS_FIXED)`;
  4. on `KERN_SUCCESS`, require `address == start`, then call
     `mach_vm_protect(task, address, length, 0,
     mach2::vm_prot::VM_PROT_NONE)`;
  5. if protection fails, immediately call `mach_vm_deallocate` and return a
     `Kernel` error;
  6. return `Reserved(DirectVmReservation { ... })` only after protection
     succeeds.

  Add a safety comment explaining that `VM_FLAGS_FIXED` requests the exact
  address while overwrite is a separate flag which Carrick deliberately does
  not pass.

- [ ] **Step 3: Keep only the strict no-space fallback.**

  If allocation returns `mach2::kern_return::KERN_NO_SPACE`, run the existing
  basic and extended Mach region queries. Accept only the canonical
  `VM_MEMORY_SHARED_PMAP | VM_MEMORY_UNSHARED_PMAP`, `SM_EMPTY`, read-only,
  reserved tuple which covers the whole requested range.

  Return `DirectVmReservationError::Kernel` immediately for every other Mach
  return. Rename query operation strings from “after redirected mmap” to
  “after fixed allocation no-space”. Remove the now-unreachable `Redirected`
  error variant and its `Display` arm.

- [ ] **Step 4: Pair guard cleanup with Mach deallocation.**

  Change `DirectVmReservation::drop` to call
  `mach2::vm::mach_vm_deallocate(mach_task_self(), address, length)` while
  armed. This works both before replacement and after an in-progress
  `MAP_FIXED` target mapping has replaced the reservation. Keep `commit()` as
  the ownership-transfer boundary.

## Task 3: Tighten the reservation safety tests

**Files:**

- Modify: `crates/carrick-host/src/host_proc.rs`

- [ ] **Step 1: Make the split-range test GREEN.**

  ```bash
  cargo test -p carrick-host fork_child_split_canonical_gap_is_reserved_exactly -- --nocapture
  ```

  Expected: the exact Mach reservation succeeds, the guard releases it, the
  source sentinel remains `0x5e`, and the nested child exits zero.

- [ ] **Step 2: Update the old one-page fork expectation.**

  Rename `fork_child_canonical_unnested_dyld_gap_is_accepted` to
  `fork_child_canonical_unnested_dyld_gap_is_owned_exactly` and require
  `Reserved(_)` for the vacant target page. Keep
  `canonical_dyld_delegated_empty_tuple_is_accepted` as the strict fallback
  test for a range which cannot be privately acquired.

- [ ] **Step 3: Run the complete reservation test module.**

  ```bash
  cargo test -p carrick-host direct_vm_reservation_tests -- --nocapture
  ```

  Expected: all tests pass. In particular:

  - exact scratch reservation rolls back correctly;
  - a canonical sentinel is rejected and its byte is preserved;
  - guard and generic shared/read-only regions remain rejected;
  - the Node-sized split tail is privately owned at the requested address.

- [ ] **Step 4: Run formatting and targeted lint gates.**

  ```bash
  just fmt-check
  cargo clippy -p carrick-host --all-targets -- -D warnings
  ```

  Expected: both pass with no new raw Mach declarations or lint exceptions.

## Task 4: Prove the originating native exec workloads

**Files:**

- Modify: `docs/native-default-conformance-campaign.md`
- Evidence: `target/conformance/native-direct-reservation-*.jsonl`

- [ ] **Step 1: Build and codesign the current CLI.**

  ```bash
  just build
  ```

  Expected: the release CLI is relinked and signed.

- [ ] **Step 2: Run the LTP eventfd case which invoked gzip.**

  ```bash
  CARRICK_RUN_ID=native-direct-eventfd01 \
    just conformance full --lane macos-native-dsr --workers 1 \
    --suite ltp-eventfd01 \
    --jsonl target/conformance/native-direct-reservation-eventfd01.jsonl \
    --force
  ```

  Expected: no Direct reservation collision or Carrick crash. Compare the
  completed content verdict with the cached Docker oracle; do not call a
  different content mismatch fixed by this mapping change.

- [ ] **Step 3: Run both Node smoke suites serially.**

  ```bash
  CARRICK_RUN_ID=native-direct-node \
    just conformance full --lane macos-native-dsr --workers 1 \
    --suite node-app-smoke --suite node-v8-smoke \
    --jsonl target/conformance/native-direct-reservation-node.jsonl \
    --force
  ```

  Expected: both suites complete without the measured
  `0x4_0002_4000..0x4_062a_4000` collision.

- [ ] **Step 4: Sample the three suites under load.**

  Repeat the eventfd and Node command set three times with `--workers 4`,
  distinct scoped run ids, and JSONL paths ending in `load-r1`, `load-r2`, and
  `load-r3`.

  Expected: no `TIMEOUT`, `CARRICK_CRASH`, or load-only verdict. If any run
  hangs, capture LLDB/event-ring evidence before changing VM logic.

- [ ] **Step 5: Record only measured results.**

  Add ledger rows for the host red/green test, serial eventfd/Node runs, and the
  three loaded samples. Mark the P0 cluster closed only if every originating
  collision is absent and the content verdicts are stable.

## Task 5: Commit the exact reservation fix

**Files:**

- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `crates/carrick-host/Cargo.toml`
- Modify: `crates/carrick-host/src/host_proc.rs`
- Modify: `docs/native-default-conformance-campaign.md`

- [ ] **Step 1: Review scope and dependency changes.**

  ```bash
  git diff --check
  git status --short
  git diff -- Cargo.toml Cargo.lock crates/carrick-host/Cargo.toml \
    crates/carrick-host/src/host_proc.rs \
    docs/native-default-conformance-campaign.md
  ```

  Expected: only `mach2`, the exact allocation implementation/tests, and
  measured ledger entries are present. Leave unrelated untracked files alone.

- [ ] **Step 2: Commit with verification receipts.**

  Use a commit such as:

  ```text
  fix(native): reserve direct exec ranges exactly

  Hint-based mmap redirected vacant split dyld ranges and rejected Node and
  gzip exec replacements. Acquire the requested interval with fixed,
  non-overwriting Mach allocation and retain the strict delegated-dyld fallback.

  Verified with collision-preservation host tests and repeated signed Node and
  ltp-eventfd01 native-lane runs.

  Co-Authored-By: Codex <codex@openai.com>
  ```
