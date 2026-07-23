# NativeLane Seam Phase-1: Closing Gate + Duplication Metrics (2026-07-23)

Task 8 of the Phase-1 plan: the closing cross-platform gate run plus the
duplication metrics the plan was chartered against. Branch
`feat/native-lane-seam-phase1`, HEAD `9a4b0c14` (`b88f9e80` + the bonus
test-gate commit below), 7 prior tasks landed and review-approved.

## Verdict

| Check | Requirement | Result |
| --- | --- | --- |
| macOS `just ci` | green, or only provably-pre-existing failures | Every failure traced to a specific pre-branch commit/behavior; **0 regressions** from this campaign's 29-file diff |
| FreeBSD `cargo test -p carrick-runtime` (full lib) | first full-scope run this campaign | 1 pre-existing cross-platform gating gap (`native_darwin` un-gated on FreeBSD) + 5-6 pre-existing flaky lib tests, all outside the diff |
| FreeBSD LTP gate (25-case) vs Task 4 baseline | pass-set MUST be identical | **IDENTICAL**: 23 pass / 2 conf, same two conf cases |
| Box left clean | restored to original branch | Restored to `perf/native-xstate-transfer` @ `65eb0b36`, clean |

## 1. macOS `just ci`

`just ci` runs `fmt-check → clippy → lint-domains → deny → check-matrix →
check --workspace → doc → test → test-integration` sequentially
(`set -euo pipefail` per step), so the first failing step aborts the rest.
Each step below was therefore also run standalone to get full-pipeline
coverage after the first abort.

### Classification table

| Step | Result | Failure | Pre-existing? | Evidence |
| --- | --- | --- | --- | --- |
| fmt-check | PASS | — | — | — |
| clippy | PASS | — | — | — |
| lint-domains | **FAIL** | `semgrep.carrick-no-function-local-linux-const` on `crates/carrick-dsr-aarch64/src/mapped_memory.rs:4783` (`const LINUX_PAGE`); `semgrep.carrick-no-inline-errno-negation` x5 in `crates/carrick-runtime/src/native_freebsd.rs` (lines 13326/14110/16066/16201/16324) | YES | Both blamed to `d2c54e5c6` ("feat(runtime): harden native x86 execution state", 2026-07-22 20:34, `codex@openai.com` co-author) — confirmed `git merge-base --is-ancestor d2c54e5c6 <merge-base>` = ancestor, i.e. landed on `main` **before** this branch's first commit (`9ee2bf9f`, 2026-07-23 09:10). `git diff <merge-base>..HEAD -- .semgrep justfile` = empty (rule set unchanged) |
| deny | PASS | — | — | — |
| check-matrix | PASS | — | — | — |
| check --workspace | PASS | — | — | — |
| doc | **FAIL** | `rustdoc::private_intra_doc_links`: `crates/carrick-guest-mem/src/protections.rs:268` links to private `ProtectionState` from public `MemoryProtectionsExclusiveGuard` doc | YES | Same commit `d2c54e5c6`, same ancestry proof |
| test | **FAIL then PASS** | First run: 8 failures in the documented native_darwin/dispatch flaky cluster (`overlay_dispatch_tests::reused_shared_anon_mmap_zeroes_recycled_range`, `exclusive_load_for_restores_host_lift_on_unsupported_width_error`, `exclusive_store_for_restores_host_lift_on_unsupported_width_error`, `native_prepared_mapping_{biased_layout_has_one_reservation_owner,final_protection_failure_retires_ranges,relocation_failure_retires_ranges,second_region_failure_retires_ranges,vvar_failure_retires_ranges}`) **plus** the brief's named `carrick-dsr-x86::gateway::tests::signal_xstate_roundtrip_is_complete_and_malformed_input_is_atomic` (panics `Unavailable("non-x86 host")` on this arm64 host). Applied the brief's authorized bonus fix (`#[cfg(target_arch = "x86_64")]` on the test fn); re-ran clean except the 8-test flake cluster, which is documented pre-existing (matches Task 4's report / project memory's "~8-10 native_darwin/dispatch flaky cluster" verbatim) | YES (both) | Flake cluster: exact match to Task-4-recorded set. dsr-x86 test: fixed per brief authorization, see commit below |
| test-integration | **FAIL** | `syscall_mem::mremap_bootstrap_accepts_shrinking_and_rejects_growth_with_enomem` (assertion mismatch, `Errno(95)` vs `Errno(22)`); `syscall_table::dispatch_declares_no_abi_constants` (`const LINUX_IPPROTO_ICMP` declared in `dispatch/net.rs` instead of `linux_abi.rs`) | YES | `LINUX_IPPROTO_ICMP` blamed to `3b11503d9` (2026-07-18), ancestor of merge-base. `mremap` test's code path (`syscall_mem.rs`, dispatch mem handling) does not appear anywhere in `git diff <merge-base>..HEAD --stat` (29 files touched, all native/dsr/lane-facade scope — see §3) |

**No regression traced to this campaign.** The full file-level diff between
the branch's merge-base and HEAD touches exactly 29 files (Cargo.lock,
docs, `AGENTS.md`, and the native/dsr facade + lane-trait + fork-child
files); none of the failing tests' code paths appear in that list.

### Bonus fix landed

`9a4b0c14` — `test(dsr-x86): gate cpuid-dependent test to x86 hosts` — adds
`#[cfg(target_arch = "x86_64")]` to
`signal_xstate_roundtrip_is_complete_and_malformed_input_is_atomic`,
matching the existing `fsgsbase_supported()` `#[cfg(target_arch =
"x86_64")]` / `#[cfg(not(target_arch = "x86_64"))]` split pattern already
used elsewhere in `gateway.rs`. Verified: `cargo test -p carrick-dsr-x86
--lib` on this arm64 host now reports `116 passed; 0 failed` (the test
compiles out entirely rather than panicking).

## 2. FreeBSD box (`root@fbsd`, target `x86_64-unknown-freebsd`)

Box was clean before and after (`git status --short` empty); restored to
`perf/native-xstate-transfer` @ `65eb0b36` at the end, matching its
state before this task.

Pushed `fbsd HEAD:refs/heads/seam-t8` (`b88f9e80`, later re-checked at the
same commit — the bonus commit above is macOS/dsr-x86-only and doesn't
change any FreeBSD-reachable code).

### Full `cargo test -p carrick-runtime --no-default-features --features platform-freebsd` (lib)

This is the first time this campaign (or, per the evidence below, possibly
ever) ran the **unscoped** `--lib` suite on FreeBSD — Task 4's baseline
only exercised the narrower `--test native_freebsd_x86` integration
target. The unscoped run **crashed the test process**:

```
error: test failed, to rerun pass `-p carrick-runtime --lib`
Caused by:
  process didn't exit successfully: `.../carrick_runtime-...` (signal: 4, SIGILL: illegal instruction)
```

Root cause: `crates/carrick-runtime/src/lib.rs` declares `pub(crate) mod
native_darwin;` with **no** `cfg(target_os = ...)` gate at all (unlike
`native_freebsd`, which is `#[cfg(all(target_os = "freebsd", target_arch =
"x86_64"))]`). Individual Darwin/AArch64-specific items inside
`native_darwin.rs` are gated (`#[cfg(target_os = "macos")]` /
`#[cfg(all(target_os = "macos", target_arch = "aarch64"))]` sprinkled
throughout), but its `dsr::` self-test module actually emits and executes
AArch64 machine code as part of some tests — which SIGILLs when that code
runs on an x86_64 CPU. **Confirmed pre-existing**: `git blame` on the mod
declaration shows it unchanged since `518ebe052` (2026-07-09, two weeks
before this campaign's first commit), and `git show
<merge-base>:crates/carrick-runtime/src/lib.rs` has the identical
ungated declaration. The project's own `justfile` already documents an
analogous, accepted category of gap ("The `integration` suite has some
macOS-only test bodies that aren't cfg-gated ... those fail/skip
ENVIRONMENTALLY off-macOS, not because of feature wiring") — this is the
same class of issue, just a harder failure mode (crash vs. skip), and the
`--lib` suite specifically had never been run to find it. Fixing
`native_darwin`'s cross-platform gating is a substantial, unrelated
engineering task and explicitly out of scope for this Phase-1 seam plan;
flagged here as a real finding, not chased. `just test`'s off-macOS branch
would hit the identical crash if ever run on this box, since
`carrick-runtime` is in its `_platform_crates` closure — **this is a
standing gap in the project's own FreeBSD gate, not something introduced
by Tasks 1-8.**

Re-ran with `-- --skip native_darwin` to get complete coverage of
everything else:

- **HEAD (`b88f9e80`/`seam-t8`)**: `786 passed; 6 failed; 229 filtered out`
- **Merge-base baseline (`a2b3875e`, detached)**: `783 passed; 5 failed; 229 filtered out`

Failures (HEAD): `dispatch::net::support::tests::host_fd_has_oob_detects_pending_urgent_byte`,
`dispatch::overlay_dispatch_tests::reused_shared_anon_mmap_zeroes_recycled_range`,
`fs_backend::tests::host_deep_path_ops_beyond_path_max`,
`native_freebsd::identity_raw_range_tests::calibrated_x86_vvar_tracks_host_clocks`,
`native_freebsd::identity_raw_range_tests::shared_waiter_key_follows_vnode_offset_not_mapping_address`,
`native_freebsd::tests::virtual_x87_wait_faults_without_touching_host_fpu_state`.
5 of these 6 reproduce identically on the merge-base baseline (only
`shared_waiter_key_follows_vnode_offset_not_mapping_address` didn't fail
in that one baseline run — but `git diff <merge-base>..HEAD --stat`
confirms `native_freebsd.rs`'s only changes are in
`fork_child_rebuild`/`native_after_fork_child`/the new fork_child test
module (4 hunks, all around lines 11355-11450 and the trailing test
module); nothing near this test's `freebsd_shared_waiter_key` code
(lines ~1520-1540) changed between baseline and HEAD — so this is
test-order/timing flake, not a regression, consistent with this
project's documented load-sensitivity of its test suite). The total-test-
count difference (792 vs 788) is fully explained by the 4 new tests
Phase-1 itself added (`native::tests::*`, `native::fork_child::tests::*`,
`native_freebsd::tests::x86_64_user_va_end_exclusive_constant_matches_dsr_x86`).

**Net: zero test failures traced to the Phase-1 diff on FreeBSD.**

### LTP gate — pass-set vs Task 4 baseline

Built `cargo build --example native_run -p carrick-runtime
--no-default-features --features platform-freebsd` (clean), then ran the
same invocation Task 4's report recorded:

```
python3.11 scripts/native-x86-ltp-gate.py \
  --ltp-bin-root /tmp/carrick-ltp-readiness/src/testcases/kernel/syscalls \
  --rootfs /tmp/carrick-ltp-image-context/rootfs \
  --output /tmp/seam-t8-b88f9e80.jsonl --timeout 120
```

Result: **25/25 cases ran; 23 pass, 2 conf (`eventfd06`, `clock_gettime03`
— the documented libaio/`CONFIG_TIME_NS` skips), exit 0.** Identical to
Task 4's recorded baseline (`23 pass, 2 conf`, same two conf cases) and to
Task 4's facade-commit run. Case list, pass/fail per case, and TPASS
counts all match Task 4's report line for line (`getpid01` TPASS=100,
`getpid02` TPASS=2, `uname01/02/04`, `eventfd01-05` pass +
`eventfd06` conf, `fork01`, all `futex_*`, `clock_gettime01/02/04` pass +
`clock_gettime03` conf).

## 3. Duplication metrics

| Metric | Baseline (pre-campaign) | Now | Delta |
| --- | --- | --- | --- |
| Same-name twin-fn count between the two lane files | 43-44 | **43** | flat (see below) |
| `native_darwin.rs` line count | — | **12,952** | — |
| `native_freebsd.rs` line count | — | **19,687** | — |
| `grep -rn "NativeLane" crates/ --include=*.rs \| wc -l` | 0 | **18** | +18 |
| `native_darwin::run_`/`native_freebsd::run_` in `execute.rs`/`runtime.rs`/`lib.rs` | N/A (direct calls existed) | **0** | facade fully routes all 5 call sites |

### Twin-fn method (reproduced exactly)

Per lane file, `grep -oE '^\s*(pub )?(unsafe )?fn [a-z_0-9]+'` over the
non-test region (everything before that file's trailing `#[cfg(test)] mod
tests { ... }` block — `native_darwin.rs:1..5880`,
`native_freebsd.rs:1..17561`), function-name column only, `sort -u`, then
`comm -12` (names present in both) piped to `wc -l`:

```
native_darwin.rs non-test fn names (unique): 187
native_freebsd.rs non-test fn names (unique): 400
comm -12 (same name in both lanes):           43
```

The 43 shared names span the whole surface a `NativeLane` impl would
eventually unify: register accessors (`get_reg`/`set_reg`/`get_fpcr`/
`get_fpsr`/`get_sys_reg`/`set_sys_reg`/`get_vreg`/`set_vreg`), execution
control (`next_syscall`/`complete_syscall`/`current_pc`/`execve_into`/
`fork`/`new`/`drop`/`request`), memory protection (`protect_range`/
`protections`/`set_mapping_protection`/`set_mapping_protection_and_sharing`/
`set_mapping_sharing`/`set_no_access`/`set_no_write`/`set_unmapped`/
`unmap_range`/`repoint_private`/`guest_range_is_writable`/
`host_ptr_for_read`/`host_ptr_for_write`), signal/fork plumbing
(`inject_signal`/`restore_from_sigframe`/`native_after_fork_child`/
`spawn_clone_thread`/`bind_current`/`wait_native_vfork_completion`/
`shared_futex_location`/`supports_concurrent_exec_protection`), and raw
I/O (`read_bytes_raw`/`write_bytes_raw`/`write_bytes`/`last_syscall_nr`).

### Why the count didn't drop

Phase 1's chartered scope was the **wiring seam** (`native/mod.rs`'s
facade + the shared `fork_child` dispatcher-reset helper), not merging
the lane bodies themselves. The one twin-fn pair Phase 1 *did* partially
converge — `native_after_fork_child` — kept its name identical in both
files (by design, so the drift-guard/facade routing stays legible) while
its *body* now delegates to the shared `crate::native::fork_child::
dispatcher_after_fork_child` helper on both lanes; grep-by-name can't see
that consolidation, only line-level diffing can (see Task 5's report).
The remaining 42 pairs are untouched — they're exactly the candidates
Phase 2 is chartered to attack.

### Facade drift-guard evidence

`crates/carrick-runtime/src/native/mod.rs`'s
`native_entry_points_route_only_through_the_facade` test (`include_str!`
over `execute.rs`/`runtime.rs`/`lib.rs`, asserting neither
`"native_darwin::run_"` nor `"native_freebsd::run_"` appears) still
passes: `cargo test -p carrick-runtime --lib native:: → 3 passed; 0
failed`. Direct grep corroborates it structurally (not just via the
test): `grep -n "native_darwin::run_\|native_freebsd::run_"
crates/carrick-runtime/src/{execute,runtime,lib}.rs` → **0 matches**.

## 4. What Phase 1 did NOT do (honest scope note)

Phase 1 built the wiring seam — `NativeLane`/`GuestIsa`/`NativeHost`
traits (`carrick-dsr/src/lane.rs`), the single `native/mod.rs` facade
routing all 5 call sites that used to call `native_darwin`/
`native_freebsd` directly, and one shared fork-child dispatcher-reset
helper (`native/fork_child.rs`) — but did not touch the substance of
either lane's implementation. Concretely, still outstanding for Phase 2
(the plan's own pointer list):

- **The 42 remaining twin-fn pairs are still two independent
  implementations**, not one generic body parameterized over
  `NativeLane` — the facade's four entry functions still branch per-target
  and call straight into `native_darwin::`/`native_freebsd::` internals
  (documented in `native/mod.rs`'s own module doc as "strangler-interim,
  NOT the end-state").
- **`IdentityGuestMemory` + checked-copy + `NativeMapping` machinery**
  (~2K lines, the direct NetBSD-reuse play) is still inline per-lane, not
  factored into a neutral identity-memory module keyed on `GuestIsa`
  consts.
- **The generic thread-loop/dispatch merge** is unbuilt:
  `run_native_dsr_thread_loop_profiled` (Darwin, 855 lines) and
  `run_x86_thread` (FreeBSD, 1750 lines) remain two separate functions,
  not one body behind `NativeLane`.
- **FreeBSD does not use `prepared_image`/`native_exec_capsule`** the way
  Darwin does; its OCI-native path is still the bytes-based
  `run_static_x86_elf_bytes` call routed through `run_dispatch_native_bytes`
  (Task 4's documented Site-A/Site-B shape asymmetry), not
  `parse_loadable_elf` replaced by the shared prepared-image path.
- **The cross-process futex host trait** (umtx vs `__ulock` +
  waiter-table) and **`carrick_dsr::cache::TranslationCache` adoption by
  the x86 lane** (replacing its inline `CachedBlock`) are both untouched.
- **`native_darwin`'s cross-platform module gating** (§2 above) is a
  pre-existing gap this task surfaced but did not fix — worth its own
  follow-up regardless of Phase 2's fn-merging agenda, since it currently
  means the project's own off-macOS `just test`/`just ci` would crash if
  ever run unscoped on a FreeBSD or Linux host.

Each Phase 2 candidate carries the same LTP-gate-equivalence acceptance
bar used in Tasks 4 and 8 (identical pass-set vs. the last-known-good
baseline before merging any lane body).
