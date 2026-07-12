# DSR exec image-map decomposition plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` task-by-task. Steps use checkbox (`- [ ]`)
> syntax for durable progress tracking.

**Goal:** Attribute the remaining approximately 1.0 ms DSR exec image-map
interval to Darwin mapping, byte copy, instruction-cache publication, final
protection, vDSO relocation/vvar stamping, and unaccounted construction work,
then write the next optimization plan only when one stable component explains
at least 30% of image-map p50.

**Why now:** The first selected candidate removed both DSR source I-cache
publications, but improved image-map p50 by only 3.5% and outer exec-reset by
1.8%. That candidate was restored. Image mapping remains the largest exec
subphase, but the evidence rules out cache publication as its dominant
mechanism.

**Architecture:** Extend the existing typed `DsrCacheLifecyclePhase` ABI with
five nested begin/end pairs. Emit them only while `replace_image` maps an exec
replacement by threading its typed DSR thread id into the mapping helpers;
initial process mapping and non-DSR paths emit nothing. Pair repeated intervals
per pid/tid in `dsr-fork.d`, aggregate them into one total per component per
exec, and retain the existing outer image-map interval as the accounting
boundary.

**Components:**

- Darwin mapping: every fixed image/trampoline mapping and the four anonymous
  heap/mmap/shared/private aperture mappings;
- byte copy: each non-empty source-to-fixed-map copy;
- I-cache publication: each existing source/trampoline publication, unchanged;
- final protection: every post-copy `mprotect`;
- vvar: vDSO/vvar relocation and freshly stamped vvar work;
- unaccounted: outer image-map minus the five measured totals, covering Rust
  region metadata, protection bookkeeping, generation-table construction, and
  translator ownership.

**Acceptance:** a signed 220-exec profile exits naturally with 220 outer
image-map intervals, exactly one aggregate row per detail and exec, zero
drops/incomplete pairs, non-negative unaccounted time for every exec, and the
sum of detail totals bounded by its matching outer interval. Repeat once; rank
must be stable and the selected component must contribute at least 30% of
image-map p50. Otherwise publish the profile as non-selecting.

---

### Task 1: Pin the typed detail ABI and DTrace surface red

**Files:**
- Modify: `crates/carrick-observability/src/probes.rs`
- Modify: `crates/carrick-cli/tests/trace_profile.rs`

- [x] **Step 1: Add ordinals 15 through 24**

Add stable pairs for `ExecMapMmap`, `ExecMapCopy`, `ExecMapIcache`,
`ExecMapProtect`, and `ExecMapVvar`. Extend the ordinal/uniqueness test.

- [x] **Step 2: Extend the script-surface test red**

Require `dsr-fork.d` to emit sampled and incomplete rows named
`exec-map-mmap`, `exec-map-copy`, `exec-map-icache`, `exec-map-protect`, and
`exec-map-vvar`.

```bash
cargo test -p carrick-observability dsr_probe_abi --lib -- --nocapture
cargo test -p carrick-cli --test trace_profile \
  fork_profile_pairs_repair_reset_and_first_prepare_latency -- --nocapture
```

Expected: the ordinal test passes; the script-surface test fails because the D
program does not yet produce the five rows.

Observed: all five typed ABI tests pass; the script-surface test fails first at
`missing exec-map-mmap sample`.

- [x] **Step 3: Commit the red surface**

Use `test(trace): pin DSR exec map detail phases` and record the exact red
assertion.

---

### Task 2: Emit nested mapping-detail boundaries

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `scripts/dtrace/dsr-fork.d`

- [x] **Step 1: Thread typed exec-only context**

Add an `Option<crate::thread::ThreadId>` detail context to
`map_with_code_mode_and_translator`, `map_region`, and `map_bytes_region`.
Every initial/test mapping passes `None`; `replace_image` passes its `dsr_tid`.
Use one helper that emits a typed lifecycle phase only for `Some(tid)`.

- [x] **Step 2: Bracket the five components**

Bracket each relevant `mmap`, copy, I-cache publication, and `mprotect` without
moving the operation or changing its condition. Bracket the vDSO relocation
inside the image loop and `stamp_vdso_vvar` under the same vvar total. Bracket
each of the four anonymous aperture mappings as Darwin mapping time.

- [x] **Step 3: Aggregate repeated intervals per exec**

In `dsr-fork.d`, keep a mapping-detail pairing state separate from the existing
outer subphase state. Add each completed nested interval to the matching
per-pid/tid total. At outer `ExecImageMapEnd` (ordinal 8), print exactly one
sample for each component, clear totals, and report open/overwrite/missing
pairs at `END`.

- [x] **Step 4: Verify and commit**

```bash
cargo test -p carrick-observability dsr_probe_abi --lib -- --nocapture
cargo test -p carrick-cli --test trace_profile -- --nocapture
cargo test -p carrick-runtime \
  native16k_dsr_exec_protection_preserves_linux_syscall_words --lib -- --nocapture
cargo clippy -p carrick-observability -p carrick-runtime -p carrick-cli \
  --lib --tests -- -D warnings
```

Use `diagnostics(native): decompose DSR exec image mapping`.

---

### Task 3: Collect, reconcile, and select

**Files:**
- Create: `docs/perf-results/native-dsr-exec-map-decomposition-v1.jsonl`
- Modify: `docs/native-dsr-dtrace-profile.md`
- Modify: this plan
- Modify: `docs/superpowers/plans/2026-07-12-dsr-profile-driven-performance.md`

- [x] **Step 1: Build signed and run two profiles**

```bash
just build
otool -l target/release/carrick | grep -A2 __dof_carrick
CARRICK_RUN_ID=dsr-map-detail-v1 target/release/carrick trace \
  --profile dsr-fork \
  --trace-out target/conformance/dsr-map-detail-v1.raw \
  --summary-jsonl target/conformance/dsr-map-detail-v1.jsonl -- \
  run-elf --raw --exec-backend native \
  --native-page-profile native16k --native-code-mode dsr \
  conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/perf_fork_exec
CARRICK_RUN_ID=dsr-map-detail-v2 target/release/carrick trace \
  --profile dsr-fork \
  --trace-out target/conformance/dsr-map-detail-v2.raw \
  --summary-jsonl target/conformance/dsr-map-detail-v2.jsonl -- \
  run-elf --raw --exec-backend native \
  --native-page-profile native16k --native-code-mode dsr \
  conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/perf_fork_exec
```

- [x] **Step 2: Reconcile exact per-exec accounting**

Join rows by pid/tid. For each of 220 execs in each run, compute `unaccounted =
exec-image-map - sum(five details)`. Reject negative values, missing rows,
non-natural completion, any drop/incomplete pair, or mismatched pid/tid sets.
Publish compact p50/p95/min/IQR, fractions, binary/profile hashes, host/power,
and completion facts in the checked-in JSONL; keep raw files local by hash.

- [x] **Step 3: Apply the deterministic selection rule**

Select the same largest component only when it contributes at least 30% of
image-map p50 in both runs and ranking is stable. Write and immediately execute
a focused child plan with a red mechanism test and a fixed 10% outer exec-reset
gate. If no component qualifies, record no selection and continue with the
umbrella gateway benchmark rather than guessing.

**Observed:** byte copy contributes 61.94% and 62.25% and ranks first in both
runs. Every one of 220 pid/tid sets per run reconciles with a non-negative
residual. Copy qualifies, with the explicit caveat that repeated enabled probe
cost is inside these diagnostic intervals. The selected child plan is
`docs/superpowers/plans/2026-07-12-dsr-exec-copy-performance.md` and begins with
low-perturbation aggregate validation.

- [x] **Step 4: Commit**

Use `docs(native): attribute DSR exec image mapping`; the body must name both
profile hashes, exact ranking, accounting residual, and the selected or
non-selecting decision.
