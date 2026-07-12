# DSR exec image-copy performance plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` task-by-task. Steps use checkbox (`- [ ]`)
> syntax for durable progress tracking.

**Goal:** Determine the low-perturbation cost of materializing an exec image
into Darwin fixed mappings, remove the proven redundant 8 MiB initial-stack
prefix copy, and reconsider page-aligned immutable backing only after the
remaining ELF payload is reprofiled.

**Current evidence:** repeated nested DTrace boundaries rank byte copy at
61.94% and 62.25% of profiled image-map p50 in two exact 220-exec runs. Those
boundaries also raise the guest benchmark p50 from roughly 11.2 ms to roughly
14.0 ms, so they identify a surface but cannot justify a representation change
on their own.

**Architecture boundary:** `carrick-mem::MemoryRegion` currently stores a
`Vec<u8>`. The initial-stack builder materializes all 8 MiB even though its
initialized argv/env/auxv window begins near the top. Native mapping already
creates a zero-filled 8 MiB extent, so it can copy only the suffix beginning at
the authoritative initial SP without changing `MemoryRegion` yet. This is the
smallest semantic seam and the first candidate. Page-aligned immutable ELF
backing via `memmap2` and the existing `OwnedHostMapping` Mach remap abstraction
remains a later ecosystem-leveraged option; no in-process exec cache is allowed
because forked host processes would diverge.

**Promotion gates:** exact workload output and DSR generation/fault tests;
Rust static PIE, Rust dynamic PIE, Go PIE, direct V8, vfork and non-leader exec;
two 220-exec profiles with zero drops/incomplete rows; untraced
`perf_fork_exec` p50 improves at least 10% with a 95% bootstrap upper ratio
below 0.95; syscall-floor and direct V8 do not regress beyond their existing
1% gates. If any gate fails, retain only the profiler and architecture audit.

---

### Task 1: Replace repeated detail probes with aggregate timing

**Files:**
- Modify: `crates/carrick-observability/src/probes.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `scripts/dtrace/dsr-fork.d`
- Modify: `crates/carrick-cli/tests/trace_profile.rs`

- [x] **Step 1: Add a typed aggregate probe red**

Add `DsrExecMapDetailKind::{Mmap, Copy, Icache, Protect, Vvar}` and
`dsr_exec_map_detail(tid, kind, duration_ns, bytes, operations)`. Pin exact
ordinals, uniqueness, real/stub signatures, and five script output rows.

Observed: all typed ABI tests pass; the script contract fails at
`missing dsr-exec-map-detail`.

- [x] **Step 2: Accumulate only in runtime-profile mode**

When `CARRICK_DSR_PROFILE` is present, use monotonic host timing around the
existing operations and accumulate duration, bytes, and operation count in one
exec-local typed struct. Emit five aggregate probes immediately before outer
`ExecImageMapEnd`. When absent, do not read the clock or mutate counters.
Remove the high-frequency lifecycle detail emissions; retain ordinals 15–24 as
reserved ABI values but no longer fire them.

- [x] **Step 3: Verify the lower-perturbation profile**

Run two signed 220-exec profiles with the same command and reconcile the five
aggregate rows to the outer interval. Require copy to remain first and at least
30% in both runs. Compare guest `fork_exec_p50_us` with the two nested-profile
runs; aggregate profiling must reduce that enabled overhead by at least 10%.
If copy falls below 30%, publish a non-selection and continue with the umbrella
gateway benchmark.

Observed: copy remains first at 89.34% and 88.43% in two exact 220-exec
runs, moving 8,904,704 bytes in six operations. Aggregate-profile guest p50 is
14.7% and 12.8% below the two nested-profile runs, passing the 10% overhead
reduction gate.

- [x] **Step 4: Commit**

Use `diagnostics(native): aggregate DSR exec map timing` with exact before/after
profile overhead and component rank.

---

### Task 2: Skip the initial stack's already-zero prefix

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Test: `crates/carrick-runtime/src/native_darwin.rs`

**Evidence:** every profiled exec copies 8,904,704 bytes. The fixture ELF is
517 KiB, while `build_linux_initial_stack` allocates an 8 MiB zero vector and
writes argv/env/auxv only near its top. Darwin's fresh anonymous stack mapping
is already zero-filled. The initialized stack suffix begins at the authoritative
`AddressSpace::initial_stack_pointer`; copying the zero prefix is redundant.

- [ ] **Step 1: Pin the copy window red**

Add a pure `native_region_copy_window(region, initial_sp) -> Range<usize>`
test. For the exact Linux stack extent, require the range to begin at
`initial_sp - region.start` and end at `region.bytes().len()`. For every other
region, absent SP, or out-of-range SP, require the full byte range. Run:

```bash
cargo test -p carrick-runtime native_region_copy_window --lib -- --nocapture
```

Expected red: the helper is absent.

- [ ] **Step 2: Copy the selected window at its guest offset**

Compute the window in `map_with_code_mode_and_translator` and pass it to
`map_region`. Copy `bytes[window.clone()]` to `mapped + window.start`; report
the selected byte count to the aggregate profiler. Do not scan for zeroes, move
the stack pointer, shrink the mapped region, change protection, or alter any
non-stack mapping. Initial and exec mappings share the same Linux semantics.

- [ ] **Step 3: Verify correctness**

Run the helper test, existing initial-stack/auxv tests in `carrick-mem`, native
stack mapping tests, DSR execute protection/generation/fault tests, clippy, and
the signed Rust static/dynamic PIE, Go PIE, direct V8, vfork, and non-leader
exec campaign from the parent plan. The mapped word at SP and all success
markers must remain exact; bytes immediately below SP must remain zero.

- [ ] **Step 4: Measure and decide**

Run two 220-exec aggregate profiles. Require copy bytes to fall by at least
7.5 MiB, image-map p50 and outer exec-reset p50 to improve by at least 10%,
and exact reconciliation. Then compare distinct signed binaries in fixed ABBA
order with at least ten 200-iteration `perf_fork_exec` runs per role and 10,000
seeded bootstrap resamples. The end-to-end p50 estimate must improve at least
10% with upper ratio below 0.95. Promote only a full pass; otherwise restore
the full stack copy and publish the rejection.

---

### Task 3: Remove stack construction materialization, then reassess backing

**Files:** determined by a fresh post-Task-2 profile and a focused child plan.

- [ ] **Step 1: Reprofile outside image mapping**

Task 2 eliminates the second 8 MiB copy but `build_linux_initial_stack` still
allocates/zeroes that vector before mapping. Add attribution around exec image
construction only if end-to-end improvement is materially smaller than the
image-map gain.

- [ ] **Step 2: Specify a sparse initialized stack window**

If construction is material, extend `MemoryRegion` deliberately to represent
an initialized window at a nonzero region offset. Preserve its current
initialized-prefix behavior for all existing callers, and cover read/write,
clone, serialization, stage-1/HVF, native, x86, vDSO, and auxv consumers. Do
not disguise an 8 MiB allocation as preparation outside the measured phase.

- [ ] **Step 3: Reconsider immutable ELF backing only after reprofile**

If the remaining approximately 0.5 MiB ELF copy still contributes at least 30%
of image-map time, write the page-aligned `memmap2` plus existing
`OwnedHostMapping::remap_copy` spec. Otherwise continue to the umbrella gateway
benchmark. No in-process exec cache is allowed because forked host processes
would diverge.
