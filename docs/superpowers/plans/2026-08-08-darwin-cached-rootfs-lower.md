# Darwin Cached Rootfs Lower Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove the per-run APFS namespace clone from Darwin host-filesystem runs by mounting the digest-keyed layer cache as an immutable lower and a fresh sparse host directory as the writable upper, while preserving native exec/reexec, fork coherence, trusted-path safety, and canonical Node/Python correctness.

**Architecture:** Keep `RootFsVfs` as the single overlay/copy-up authority. Extend `RootFs` with a host-backed immutable form whose operations delegate to a read-only `HostFsBackend`; expose an exact cache-entry acquisition API; then teach direct execution and native exec capsules to bind that lower alongside the existing writable upper. The path ships default-on only after correctness and clean wall-time qualification, behind `CARRICK_FS_CACHED_LOWER=0`.

**Tech Stack:** Rust, cap-std, serde/CBOR native exec capsules, Darwin APFS clone/cache layer, Carrick host VFS, serialized runtime tests, signed release builds, cached Docker conformance oracle, DTrace/USDT.

---

## Invariants and evidence rules

- The shared cache entry is immutable after publication. Guest writes, metadata changes, renames, links, whiteouts, and tombstones go only to the per-run upper.
- The upper remains host-backed so children produced by `fork` observe writes coherently.
- Native PID-preserving self-reexec restores the exact lower and upper authorities; it must not silently fall back to a reconstructed or empty root.
- File-backed native exec remains available from the lower, including bounded executable-head reads.
- Trusted dirfd fast paths may use the lower only when overlay interference is proven absent for the relevant directory/component. Any uncertainty falls back to the existing layered resolver.
- `CARRICK_FS_CACHED_LOWER=0` selects the current per-run materialized-root behavior exactly.
- Never run Carrick and Docker concurrently. Cached-oracle conformance is allowed; any fresh oracle pass is a separate phase.
- A performance result is retained only when it is current-tip, repeatable, correctness-green, and bound to source, binary, configuration, and raw receipt.

## Task 1: Expose an immutable layer-cache entry

**Files:**
- Modify: `crates/carrick-runtime/src/layer_cache.rs`

- [x] Add a red unit test proving an acquisition call returns the same published cache directory for the same ordered layer stack without populating a scratch directory.
- [x] Add a red unit test proving a changed layer stack selects a different entry and incomplete temporary entries are never returned.
- [x] Extract the existing key/build/publish sequence from `try_seed_scratch` into `pub(crate) fn acquire_immutable_entry(layer_paths: &[PathBuf], scratch_root: &Path) -> io::Result<Option<PathBuf>>`; the explicit root keeps the entry on the same configured volume as every per-run upper.
- [x] Keep `try_seed_scratch` behavior byte-for-byte equivalent by acquiring the entry and then calling `clone_children_into`.
- [x] Document that callers receive a shared immutable authority and must never mutate it.
- [x] Run `RUST_TEST_THREADS=1 cargo test -p carrick-runtime layer_cache::tests -- --nocapture` and `cargo fmt --all -- --check`.

## Task 2: Add a host-backed immutable `RootFs`

**Files:**
- Modify: `crates/carrick-runtime/src/vfs/rootfs.rs`
- Modify: `crates/carrick-runtime/src/fs_backend.rs`

- [x] Add red `RootFsVfs` tests using a real host lower and host upper for: lower read, merged directory listing, upper shadowing, lower-only metadata, symlink metadata, deletion tombstone, and lower immutability.
- [x] Add a red test proving a writable open of a lower regular file copies it into the host upper and returns a host-backed file whose write is visible through a second VFS instance sharing that upper.
- [x] Represent `RootFs` as either the existing in-memory OCI maps or an immutable `Arc<HostFsBackend>` lower. Preserve the public type so existing `RootFsVfs`, resolver, and overlay call sites remain the single layering seam.
- [x] Implement host-backed delegation for `read`, bounded read/head, shared read, readlink, metadata, symlink metadata, directory entries, contains, and read-only host-file open.
- [x] Add an exact, serializable host-lower authority containing the canonical cache path and the identity needed to reject replacement. Re-open with containment and identity validation; never grant mutation through the lower API.
- [x] Change lower-file copy-up to materialize into the host upper and reopen as `HostFile`, retaining the existing in-memory behavior for the OCI-map variant.
- [x] Run the focused `vfs::rootfs` and `fs_backend` tests serialized, then runtime lib tests serialized.

## Task 3: Preserve file-backed exec and lower identity

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`

- [x] Add red dispatch tests proving `read_exec_file_head` performs a bounded lower read and `open_exec_host_file` returns a file from the immutable host lower when the upper has no shadow.
- [x] Add a red test proving an upper shadow wins and a tombstone prevents lower exec access.
- [x] Extend the dispatcher helpers to consult overlay first and then the lower while respecting tombstones and symlink/path resolution rules.
- [x] Keep the Tier T executable identity guards intact: mapped-span identity remains the DSR digest fallback, and legacy self-reexec still computes the full file digest when it consumes one.
- [x] Run the focused exec-loading tests; prepared-image and direct-runner qualification is retained as an explicit capsule checkpoint below.

## Task 4: Carry the immutable lower through native exec capsules

**Files:**
- Modify: `crates/carrick-runtime/src/native_exec_capsule.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs`

- [ ] Add a red capsule round-trip test showing an optional host-lower authority survives serialization and restores access to a lower-only executable after PID-preserving self-reexec.
- [ ] Add red rejection tests for a missing/replaced cache path and for a malformed authority. Old capsules without the new field must continue to deserialize via `#[serde(default)]`.
- [ ] Add `lower_rootfs` to `NativeGuestExecV1`, snapshot it in `begin_guest_exec`, validate it before destructive state changes, and restore it in `resume_guest_from_capsule` before guest execution.
- [ ] Ensure cleanup ownership remains only with the writable upper; resuming or dropping a lower authority must never delete the shared cache.
- [ ] Run all capsule/prepared-image tests and `native_darwin` exec-resume tests serialized.

## Task 5: Select cached-lower execution on Darwin

**Files:**
- Modify: `crates/carrick-runtime/src/direct_runner.rs`
- Modify: `crates/carrick-runtime/src/fs_backend.rs`
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs`
- Test: `crates/carrick-runtime/src/direct_runner.rs`

- [ ] Add a red direct-runner test proving default Darwin host-fs setup acquires the immutable cache lower, creates an empty sparse upper, and does not call the scratch clone path.
- [ ] Add a red hatch test proving `CARRICK_FS_CACHED_LOWER=0` retains the current extracted/materialized root.
- [ ] Wire the cached lower only for the Darwin native host-fs lane. Image layers build/acquire the shared cache, `HostFsBackend::new*` owns a fresh sparse upper, and `SyscallDispatcher` receives both layers.
- [ ] Preserve foreground, detached child, fork child, and exec-resume setup. Ensure each lifecycle owner has exactly one cleanup responsibility for the upper and none for the lower.
- [ ] Add a debug/test-only clone census hook or outcome enum so the no-clone assertion is structural rather than inferred from elapsed time.
- [ ] Run direct-runner tests, runtime lib tests, `cargo fmt --all -- --check`, and `git diff --check`.

## Task 6: Re-enable trusted paths over the cached lower

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/fs.rs`
- Modify: `crates/carrick-runtime/src/dispatch/pathres.rs`
- Modify: `crates/carrick-runtime/src/vfs/rootfs.rs`

- [ ] Add red tests for trusted lower-only directory open/getdents/stat, plus upper shadow, upper whiteout, symlink, rename, and newly-created-child interference cases.
- [ ] Give a trusted directory an immutable lower dirfd and an overlay-interference state. For untouched directories/components, resolve directly against the lower anchor; when the upper may affect the answer, consult it first or fall back to the existing layered resolver.
- [ ] Re-enable streamed directory materialization for lower-only immutable directories. Merge through the existing layered path whenever upper entries or tombstones exist.
- [ ] Bump/drop trusted state through the existing filesystem mutation generation so a post-open guest write cannot leave stale lower-only trust armed.
- [ ] Run focused trusted-dir/path-resolution tests and the complete runtime lib suite serialized.

## Task 7: Correctness qualification

**Files:**
- Add or modify only evidence files after successful qualification.

- [ ] Build and sign with `just build`; record source commit/tree status, binary SHA-256, Mach-O UUID, codesign verification, and all active host knobs.
- [ ] Run native smoke using the signed binary.
- [ ] Run cached-oracle Node app/V8/libuv conformance with one worker and record exact verdicts and timings.
- [ ] Run cached-oracle CPython subprocess/threading conformance with one worker and record exact verdicts and timings.
- [ ] Run `just ci` and, if required by the changed filesystem surface, `just conformance-native smoke` in the prescribed two-phase mode.
- [ ] Any regression must be reduced against the hatch and pre-change binary before a fix is attempted.

## Task 8: Mechanism and performance qualification

**Files:**
- Modify or add: `scripts/dtrace/` durable question-specific script only if existing scripts cannot answer the question.
- Add: `docs/perf-results/2026-08-08-darwin-cached-rootfs-lower.md`
- Modify: the campaign ledger/controller artifact that names Tier D status.

- [ ] Run at least three clean Node app samples with the default-on path and three hatch-off samples in alternating order, draining reapers between samples. Report wall, user, sys, CPU-seconds, median, and workload spread.
- [ ] Run `scripts/perf/container-lifecycle-split.sh` on the fs-walk/no-op fixture and bind create, in-guest, teardown, and total wall separately.
- [ ] Use DTrace to prove the per-run `clonefileat` namespace population is absent on the default-on arm and present on the hatch arm. The script must fail closed on zero lifecycle evidence and declare perturbation.
- [ ] Run the native filesystem amplification census to ensure the layered path did not regress guest-to-host syscall amplification enough to erase the lifecycle win.
- [ ] Retain the default only if clean current-tip Node total wall is repeatably at or below 2.0x Docker or materially closer with no correctness regression; otherwise keep the mechanism behind the hatch and continue trusted-path work before claiming a win.
- [ ] Write the evidence document with exact commands, raw artifact paths, source/binary/semantics provenance, ABBA table, correctness receipts, DTrace mechanism result, confidence, and residual budget.
- [ ] Update Tier D status honestly: measured default result only, with projections clearly labeled and no 1x claim absent direct evidence.

## Task 9: Final verification and integration handoff

- [ ] Re-run `cargo fmt --all -- --check`, `git diff --check`, focused serialized tests, `just ci`, signed native smoke, Node, and Python qualification on the final unchanged tree.
- [ ] Review the diff for accidental debug output, mutable lower access, cleanup ownership mistakes, stale authority acceptance, missing hatch coverage, and unrelated files.
- [ ] Use `superpowers:verification-before-completion`, then `superpowers:finishing-a-development-branch` before presenting integration options.
- [ ] Do not push or merge without the user's explicit instruction.
