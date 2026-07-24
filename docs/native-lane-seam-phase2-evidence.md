# NativeLane Seam Phase-2: Closing Gate + Metrics + Evidence (2026-07-23)

Task 5 of the Phase-2 plan (`docs/superpowers/plans/2026-07-23-native-lane-seam-phase2.md`):
the closing cross-platform gate run plus the duplication/adoption metrics the
plan was chartered against. Branch `feat/native-lane-seam-phase2`, HEAD
`2cf1eba4`, base `main @ 127bf605`. Tasks 1-4 all landed and review-approved
(9 commits: `fbc5779d`, `dd5e2552`, `59c495dc`, `c5156198`, `c977b4d9`,
`a757f0ea`, `db7cf41b`, `8cccb55a`, `2cf1eba4`).

## Verdict

| Check | Requirement | Result |
| --- | --- | --- |
| macOS `just ci` | green, or only provably-pre-existing failures | 8/9 stages PASS; `test` fails on exactly the documented §3 8-test flaky cluster — **zero new failures** |
| FreeBSD box `native_freebsd_x86` (43-case integration suite) | must equal baseline | **43/43, identical** |
| FreeBSD LTP gate (25-case) vs Task-2/3 baseline | pass-set MUST be identical | **IDENTICAL**: 25/25 ran, 23 pass / 2 conf (`eventfd06`, `clock_gettime03`); zero semantic-field diffs (programmatic JSONL diff) |
| FreeBSD unfiltered `--lib` (the SIGILL gate Task 4d closed) | still completes, same pre-existing residue | **777 passed / 5 failed** — identical failing-test set to Task 4d's proof, no SIGILL/hang |
| Box left clean | restored to original branch | Restored to `perf/native-xstate-transfer` @ `65eb0b36`, `git status` clean |

## 1. macOS `just ci`

Ran every `just ci` stage individually (staged-log pattern, continuing past
a failing stage to get full-pipeline coverage in one pass rather than
aborting at the first failure) against this branch's actual HEAD
(`2cf1eba4`).

| Stage | Result | Notes |
| --- | --- | --- |
| `fmt-check` | PASS | — |
| `clippy` | PASS | — |
| `lint-domains` | PASS | (The `d2c54e5c6`-attributed findings the Phase-1 evidence doc documented are already fixed on `main` — ancestor-confirmed: `9d58294b` is an ancestor of this branch's base `127bf605`.) |
| `deny` | PASS | — |
| `check-matrix` | PASS | — |
| `check --workspace` | PASS | — |
| `doc` | PASS | (Same reasoning: `e72606ca`'s rustdoc fix is already an ancestor of the Phase-2 base.) |
| `test` | **FAIL** — known residue only | See below |
| `test-integration` | PASS | (`257ce190`/`6e5d8efb`'s fixes for the two Phase-1-era `test-integration` failures are both ancestors of the Phase-2 base — `syscall_table::dispatch_declares_no_abi_constants` and the mremap-errno case are both green here.) |

### `test` stage classification

`cargo test --workspace --exclude carrick-runtime --lib` (parallel, all
other 26 workspace crates): **100% green**, no failures anywhere. The
serial `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib` that
follows it:

```
failures:
    dispatch::overlay_dispatch_tests::reused_shared_anon_mmap_zeroes_recycled_range
    native_darwin::tests::exclusive_load_for_restores_host_lift_on_unsupported_width_error
    native_darwin::tests::exclusive_store_for_restores_host_lift_on_unsupported_width_error
    native_darwin::tests::native_prepared_mapping_biased_layout_has_one_reservation_owner
    native_darwin::tests::native_prepared_mapping_final_protection_failure_retires_ranges
    native_darwin::tests::native_prepared_mapping_relocation_failure_retires_ranges
    native_darwin::tests::native_prepared_mapping_second_region_failure_retires_ranges
    native_darwin::tests::native_prepared_mapping_vvar_failure_retires_ranges

test result: FAILED. 1011 passed; 8 failed; 5 ignored; 0 measured; 0 filtered out; finished in 3.27s
```

**This is byte-for-byte the documented §3 flaky cluster** —
`main-health-report.md`'s own classified residue, and the *exact same 8
names, in the exact same count* (1011/8/5) that Task 2's report recorded on
this same branch three commits earlier and that Task 4d's report recorded
again after the `native_darwin` cfg-gate fix. None of these 8 tests'
code paths intersect this task's own diff (Task 5 added no code, only the
evidence doc), so there is nothing new here to trace — this is the
project's own documented, pre-existing, load-sensitive flake cluster, not a
Phase-2 regression. **Zero new failures.** No deterministic stage
(`lint-domains`/`doc`/`check`) failed, so there is no BLOCKED condition per
the task's own gate.

`test-integration` (the next stage in sequence) then ran clean — its own
process is independent of the prior stage's failure, confirming the two
Phase-1-era deterministic fixes (`syscall_table::dispatch_declares_no_abi_constants`,
the mremap-errno precedence case) both hold on this branch.

## 2. FreeBSD box

Pushed `fbsd HEAD:refs/heads/seam-p2t5` (`2cf1eba4`); box checked out clean
at that commit (`. ~/.cargo/env`, `--no-default-features --features
platform-freebsd` throughout).

### `native_freebsd_x86` integration suite

```
cargo test -p carrick-runtime --test native_freebsd_x86 --no-default-features --features platform-freebsd
```
**43 passed; 0 failed** — identical to the Task-2/3/4 baseline (43/43).

### LTP gate — pass-set vs Task-2/3 baseline

```
python3.11 scripts/native-x86-ltp-gate.py \
  --ltp-bin-root /tmp/carrick-ltp-readiness/src/testcases/kernel/syscalls \
  --rootfs /tmp/carrick-ltp-image-context/rootfs \
  --output /tmp/seam-p2t5-after.jsonl --timeout 120
```
**25/25 cases ran; 23 pass, 2 conf (`eventfd06`, `clock_gettime03`), exit 0.**

Programmatic diff (`local_status` + `exit_code` + `counts{TPASS,TFAIL,TBROK,
TCONF}` + `timed_out` per case) against the Task-2/3-recorded baseline
(`seam-p2t3-baseline.jsonl`, itself proven identical to Task-2's own
baseline): **zero diffs across all 25 cases.** `assertions` text differs in
exactly the same 4 cases Tasks 2 and 3 both already flagged (`fork01`,
`futex_wait_bitset01`, `getpid01`, `getpid02`) — nondeterministic PID values
and microsecond wait-time readings only, `counts` identical in every one.

**Verdict: baseline == after**, unchanged since Task 2.

### `--lib` unfiltered — the SIGILL gate Task 4d closed, reconfirmed

Task 4d's `native_darwin` cfg-gate fix turned a box-crashing (SIGILL) /
hanging unfiltered `cargo test -p carrick-runtime --lib` run into a clean
5-second pass. Re-ran it fresh on this task's own box session as
closing-gate evidence that the fix holds under a completely independent
checkout/build:

```
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib --no-default-features --features platform-freebsd
```
**777 passed; 5 failed; 0 ignored; finished in ~6.5s.** No SIGILL, no hang.
Failing set, byte-for-byte identical to Task 4d's documented (and
baseline-proven pre-existing) 5:
`dispatch::net::support::tests::host_fd_has_oob_detects_pending_urgent_byte`,
`dispatch::overlay_dispatch_tests::reused_shared_anon_mmap_zeroes_recycled_range`,
`fs_backend::tests::host_deep_path_ops_beyond_path_max`,
`native_freebsd::identity_raw_range_tests::calibrated_x86_vvar_tracks_host_clocks`,
`native_freebsd::tests::virtual_x87_wait_faults_without_touching_host_fpu_state`.
(`reused_shared_anon_mmap_zeroes_recycled_range` is also the documented
cross-platform macOS §3 flaky-cluster test — see `main-health-report.md`.)

`just clippy` on the box: clean, 0 warnings.

Box restored to `perf/native-xstate-transfer` @ `65eb0b36` as the last box
action; `git status --short` empty, confirmed after the restore.

## 3. Metrics

### `native_freebsd.rs` line count — the headline shrink metric

| Commit | Lines | Delta |
| --- | --- | --- |
| Phase-2 base (`127bf605`) | 19,687 | — |
| after Task 2 (`59c495dc`, identity-memory move) | 16,513 | −3,174 |
| after Task 3 (`c5156198`, cache adoption) | 16,594 | +81 |
| after Task 4 (`2cf1eba4`, carry-ins, final HEAD) | **16,593** | −1 |
| **Phase-2 net** | | **−3,094 (−15.7%)** |

Target was ≤16,000 (and −3.5K line reduction or better per the File Structure
section). Actual final: **16,593 — 593 lines over ≤16K.** Achieved −3,094
lines vs −3,500 chartered (406 short). Not hit exactly, but the substance
target (shrink the monolith by the identity-memory + cache moves) was: Task 2
alone removed 3,174 lines by moving `IdentityGuestMemory` + its whole closure
to a shared crate. Task 3's cache adoption added back +81 net (a deliberate
trade — typed `CacheError`/recycle-retry handling and doc comments explaining
the KEEP-LANE boundary are more verbose than the ~15-line hand-rolled
bump-pointer check + raw write they replaced; see Task 3's report §Metrics).
Task 4 was net −1 (small correctness fixes + the mremap dead-code removal
roughly offset the cfg-gating additions elsewhere). The 593-line miss is
attributable to Task 3's deliberate +81-line trade, the 9 deferred trailing
tests (would have reduced the count further), and plan-estimate optimism, not
scope creep.

### `native_darwin.rs` — confirmed untouched (the aarch64-lane-stability pin)

19,687/16,593 vs **12,952 → 12,952 (0 change)**, byte-identical at the base
and HEAD commits. Darwin's own memory/cache machinery was never touched by
either Task 2 or Task 3 — both are additive-only on the shared side
(`ExecutableMutationAuthority`, `IdentityHostSeam`, `TranslationCache::
from_region`, `JitRegion::sub_region`), confirming the aarch64 lane's
zero-behavior-change requirement held for the whole phase, not just per-task.

### Twin-fn count — the memory/cache-twin collapse

Reproducing the Phase-1 evidence doc's exact method: per lane file,
`grep -oE '^\s*(pub )?(unsafe )?fn [a-z_0-9]+'` over the non-test region
(`native_darwin.rs:1..5880`, `native_freebsd.rs:1..14447` — the trailing
`#[cfg(test)] mod tests` boundary moved from line 17561 to 14447 as a
consequence of Task 2's extraction), function-name column, `sort -u`, then
`comm -12` (names present in both lane files):

| Metric | Phase-1 end | Phase-2 end | Delta |
| --- | --- | --- | --- |
| Same-name twin-fn count | 43 | **29** | **−14** |
| `native_darwin.rs` non-test fn names (unique) | 187 | 187 | 0 |
| `native_freebsd.rs` non-test fn names (unique) | 400 | 304 | −96 |
| `grep -rn "NativeLane" crates/ --include=*.rs \| wc -l` | 18 | **19** | +1 (doc-comment cross-ref only, see below) |

**The 14 collapsed names** (present in `native_darwin.rs`'s twin-fn set
before Phase 2, and STILL present there today, but no longer independently
implemented in `native_freebsd.rs` at all — because they now live once, in
the shared `carrick-dsr::identity_memory` module, which `native_freebsd.rs`
calls into instead of defining):
```
protect_range, set_mapping_protection, set_mapping_protection_and_sharing,
set_mapping_sharing, set_no_access, set_no_write, set_unmapped,
unmap_range, repoint_private, guest_range_is_writable,
host_ptr_for_read, host_ptr_for_write, shared_futex_location,
supports_concurrent_exec_protection
```
Verified directly (not just by the count dropping): each of these 14 names
was grepped individually against both lane files' fn-name lists — all 14
still resolve in `native_darwin.rs` (Darwin's own `GuestMemory` impl is
unchanged, as expected) and all 14 are now **absent** from
`native_freebsd.rs`'s own fn-name list (they're `impl GuestMemory for
IdentityGuestMemory<A>` methods that moved to `identity_memory.rs` in Task
2 and are called through the shared type, not redefined locally). This is
exactly the "memory twins collapse via the shared module, not via a
generic-fn merge" mechanism the brief anticipated — grep-by-name can see it
here (unlike Phase 1's `native_after_fork_child` convergence, which kept an
identical name on both sides and needed line-level diffing to see the body
delegate).

The remaining 29 twin names are the ones Task 1's precision map explicitly
scoped OUT of Phase 2 (register accessors, execution control, signal/fork
plumbing, raw I/O) — real candidates for the Phase-3 thread-loop merge, not
touched here.

**`NativeLane` ref delta (+1) is non-functional**: the one new occurrence is
a doc-comment cross-reference added in Task 2
(`native_freebsd.rs:1238`, "single-wiring-point pattern as `native/mod.rs`'s
`HostNativeLane`") pointing at the facade for readers of the newly-extracted
identity-memory code; it adds no new trait impl, type, or call site.

### New/grown shared-crate files (the neutralization + adoption targets)

| File | Before | After | Delta | Notes |
| --- | --- | --- | --- | --- |
| `crates/carrick-dsr/src/identity_memory.rs` | — (new) | **3,185** | +3,185 | Task 2: `IdentityGuestMemory<A>` + `GuestMemory` impl + checked-copy cluster + `NativeMapping`/`NativeMappingTransaction` + raw-range gate, moved (not rewritten — see Task 2's `git diff --color-moved` evidence) |
| `crates/carrick-dsr/src/cache.rs` | 1,137 | **1,284** | +147 | Task 3 (+153, `from_region`/`owns_mapping`) then Task 4b (−6, dead `after_fork_child` test-host impls removed) |
| `crates/carrick-dsr/src/host.rs` | 122 | **204** | +82 | Task 3 (+80, `JitRegion::sub_region` + tests) then Task 4b (+2, doc comment on `end_thread_write` documenting it as the sole fork-repair path) |
| `crates/carrick-dsr-x86/src/cflow.rs` | 640 | **933** | +293 | Task 2: `ControlFlowMemory` impl for `IdentityGuestMemory<A>` forced here by Rust's orphan rule, plus 2 tests |
| `crates/carrick-native-freebsd/src/waiter_key.rs` | — (new) | **130** | +130 | Task 2: `freebsd_shared_waiter_key` behind the `NativeHost::shared_futex_waiter_key` seam |

### Total Phase-2 diff (whole `crates/` tree, `127bf605..2cf1eba4`)

**26 files changed, +4,457 insertions, −3,596 deletions (net +861 lines).**
The net-positive total, despite the headline −3,094-line shrink of
`native_freebsd.rs`, is expected and correct: most of those 3,094 removed
lines reappear as the new `identity_memory.rs` (+3,185) and `cflow.rs`
(+293) files (a redistribution, not new logic — Task 2's report proves this
with byte-level `diff` on two full extracted functions showing only the
documented mechanical substitutions). The genuinely-new lines are the
seam plumbing (`ExecutableMutationAuthority` trait, `IdentityHostSeam`,
`JitRegion::sub_region`, `TranslationCache::from_region`,
`NativeHost::shared_futex_waiter_key`/`exclusive_fixed_map_flag` defaults)
plus typed-error-handling verbosity Task 3 traded for the old bump-pointer
check, all deliberate and reported.

## 4. KEEP-LANE cache boundary (restated from Task 3)

Per the binding cache capability matrix (Task 1's notes doc, §3), Task 3
adopted **only the JIT-bytes bump-allocator** onto the shared
`carrick_dsr::cache::TranslationCache` — two new additive constructors
(`JitRegion::sub_region`, `TranslationCache::from_region`) and nothing else
in the shared crate changed. Everything presuming cross-thread sharing or
aligned-atomic single-word patch semantics **stayed lane-local**, because
adopting it would either force a lock around x86's currently lock-free
per-thread hot path (the block index) for zero behavioral gain before the
Phase-3 thread-loop merge, or — for the chain-edge patch protocol —
silently corrupt JIT code under concurrency:

- **The block index** (`CachedBlock`/`HashMap<u64, CachedBlock,
  VaBuildHasher>`, `pending`, `cflow_plans`) is per-thread-private today (no
  `Arc`, no lock); aarch64's shape (`ProcessState.blocks: BTreeMap` behind a
  shared `RwLock`) is architecturally different. Unifying this now would
  *be* the Phase-3 merge, not a Task-3 plumbing swap.
- **The chain-edge patch protocol** (`patch_slot`/`GuardedChainPatch`/
  `publish_guarded_chain_edge`) is untouched: x86 `rel32` patch sites are not
  guaranteed 4-byte aligned, and the protocol is a two-site, target-first,
  `Ordering::Release`-fenced publish — architecturally incompatible with
  `TranslationCache::patch_code_word`'s hard `is_multiple_of(4)` +
  single-`AtomicU32::store` contract. Forcing unification here is exactly
  the "corrupts JIT code under concurrency" risk the brief warned against.
- Everything else the matrix's §3b already classified KEEP-LANE/
  not-applicable (`PublishedFaultEntry`, the coarse whole-cache-flush vs
  `PageGenerationTable`'s per-page granularity, `JIT_SLICE_COUNT`/
  `JIT_SLICE_LEN`/`SharedRun::alloc_slice`/`free_slice`) — none of it was
  touched; only what each slice *becomes* (a private `TranslationCache` via
  `from_region`) changed.

One adaptation the matrix didn't fully spell out: x86 translated blocks are
an arbitrary byte length, while `TranslationCache::begin_write`/
`CacheWriter::write_words` require a nonzero `u32`-multiple length (correct
for aarch64's fixed-4-byte instructions). Rather than relax that shared,
tested invariant, the new lane-local `publish_x86_translated_bytes` helper
pads to the next 4-byte boundary with `0xCC` (`int3`) filler — never
reached, since every emitted x86 block already ends in an unconditional
jump.

## 5. Carry-in outcomes (Task 4)

- **`after_fork_child` removed** — the `NativeHostJit` trait method (+ all 7
  implementations) had zero production call sites; the real fork-repair
  path is `TranslationCache::after_fork_child` → `self.host.end_thread_write()`
  directly. Removed, documented on `end_thread_write` itself.
- **`GuestIsa::GUEST_PAGE_SIZE` removed** (YAGNI) — zero production
  consumers; the page-size decision for the one real linux4k-on-16k case
  already lives in the capability table (`page_geometry.rs`), not a
  per-ISA trait const.
- **`native_darwin` gated → SIGILL closed** — cfg-gating
  `pub(crate) mod native_darwin;` to `#[cfg(all(target_os = "macos",
  target_arch = "aarch64"))]` (mirroring `native_freebsd`'s existing gate)
  turned an entire tree of Darwin-only production plumbing (~20 items across
  8 files) from unconditionally-compiled-and-crashing-on-FreeBSD into
  correctly cfg'd dead code on that lane. This is the fix §2 of the Phase-1
  evidence doc flagged as a standing gap but explicitly left out of scope —
  closed in Phase-2 Task 4, reconfirmed as still closed in this task's own
  independent box session (§2 above).
- **Dead mremap `FIXED`/`DONTUNMAP` branches removed** — the 2026-07-23
  errno-precedence ruling's `EOPNOTSUPP` refusal is the only return before
  ~150 lines of now-provably-dead branches (`fixed_new_address`,
  `move_requested`, the FIXED-destination allocator hint, 4×
  `if move_fixed {abort} else {rollback}` pairs, the FIXED-only free-list
  bookkeeping). Deleted; the refusal itself is unchanged.
- **Fork-child region registration by actual capacity** — `fork_child_rebuild`
  now registers the fault-shim code region by `region.capacity` instead of a
  local constant that had nothing structurally to do with the region
  `remap_for_fork_child` actually returned. Numerically identical today,
  decoupled for correctness.

## 6. What Phase 2 did NOT do (honest scope note)

Phase 2 built the floor two moves stand on (shared identity-memory module +
shared JIT-bytes cache adoption) plus the Phase-1 carry-ins — it did **not**
touch the substance of either lane's execution loop or exec path. Per the
plan's own Phase-3 pointer and this task's own findings:

- **The thread-loop merge is unbuilt.** `run_native_dsr_thread_loop_profiled`
  (Darwin) and `run_x86_thread` (FreeBSD) remain two separate functions.
  They now both stand on the shared `TranslationCache`/`JitRegion` and
  shared `IdentityGuestMemory`, which is exactly what makes a future
  `NativeLane`-parameterized merge tractable — but nothing was merged this
  phase. The 29 remaining twin-fn pairs (register accessors, execution
  control, signal/fork plumbing, raw I/O) are that merge's real candidate
  list.
- **FreeBSD does not adopt `native_exec_capsule`/`prepared_image`.** Its
  OCI-native path is still the bytes-based `run_static_x86_elf_bytes` →
  `run_dispatch_native_bytes`, not the shared prepared-image path Darwin
  uses (`parse_loadable_elf`/`load_static_pie` duplication remains).
- **The cross-process futex host trait** (FreeBSD `umtx` + waiter-table vs
  Darwin `__ulock`) is untouched — both lanes still implement their own
  futex wait/wake independently.
- **NetBSD lane bring-up** was not attempted; it is the seam's own
  acceptance test per the maintainer's roadmap, deliberately sequenced
  after Phase 2's floor lands.
- **9 deferred trailing tests** — Task 2's own report (§Self-review item 7)
  cut scope on the trailing ~53-test `mod tests` block's "9 clean move
  candidates" (explicitly heuristic in Task 1's notes doc, explicitly not
  required). They were left in `native_freebsd.rs` rather than individually
  re-verified and moved; they still exercise the moved code correctly across
  the crate boundary (part of the box's 777-pass run), satisfying the
  brief's "runtime consumers pin behavior" bar, but represent unclaimed
  additional cleanup for a future pass.
- **The `≤16K` line-count target was missed by 593 lines** (16,593 actual)
  — see §3 above; achieved −3,094 vs −3,500 chartered; attributable to Task
  3's deliberate typed-error-handling trade (+81 lines), the 9 deferred
  trailing tests, and plan-estimate optimism, not scope creep or an incomplete
  move.
- **The Intel-mac cfg-proxy minor.** Task 4d's `vdso_enabled_for_debug`
  re-export gate is `cfg(any(feature = "platform-macos", all(target_os =
  "macos", target_arch = "aarch64")))` — a deliberate "union of both real
  callers' cfgs" (per its own comment) rather than `native_darwin`'s own
  strict aarch64 gate. Cargo does not tie the `platform-macos` feature to
  `target_arch`, so a hypothetical Intel-Mac build (`x86_64-apple-darwin`,
  `platform-macos` feature on) would still compile this re-export even
  though it has no `native_darwin`-side consumer on that arch. Verified
  non-breaking (the definition site in `vdso_policy.rs` uses the identical
  union, so the two stay consistent — no unresolved-symbol risk), but it is
  a looser proxy than a precise "is this the Darwin/aarch64 native lane"
  gate would be. Not tightened this phase; flagged as a minor gate-precision
  debt, not a bug.

Each Phase 2 change carries the same LTP-gate-equivalence acceptance bar
used throughout Phase 1: identical pass-set vs. the last-known-good baseline
before merging any lane-adjacent behavior, verified fresh in this task's own
independent box session, not just inherited from Tasks 2-4's own runs.
