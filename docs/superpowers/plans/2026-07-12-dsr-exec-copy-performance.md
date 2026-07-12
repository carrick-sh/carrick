# DSR exec image-copy performance plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` task-by-task. Steps use checkbox (`- [ ]`)
> syntax for durable progress tracking.

**Goal:** Determine the low-perturbation cost of materializing an exec image
into Darwin fixed mappings and, only if copy remains at least 30% of image-map
time, replace the redundant second materialization with page-aligned immutable
backing that Darwin can map copy-on-write.

**Current evidence:** repeated nested DTrace boundaries rank byte copy at
61.94% and 62.25% of profiled image-map p50 in two exact 220-exec runs. Those
boundaries also raise the guest benchmark p50 from roughly 11.2 ms to roughly
14.0 ms, so they identify a surface but cannot justify a representation change
on their own.

**Architecture boundary:** `carrick-mem::MemoryRegion` currently stores a
`Vec<u8>`. ELF loading first copies file spans into that vector; native exec
then copies the vector a second time into fresh anonymous fixed mappings. A
page-aligned immutable region backing could preserve the first materialization
and let Darwin install a private COW view with the existing
`mach_vm_remap(copy=TRUE)` mechanism in `carrick-host`. This is a cross-cutting
memory-representation change, not a local `memcpy` tweak. Do not add an
in-process exec-path cache: forked host processes would diverge, and validating
file identity/staleness would be a separate semantic project.

**Ecosystem leverage:** use `memmap2` for portable RAII page-aligned backing
(already present in `Cargo.lock`) and extend the existing
`carrick_host::host_mapping::OwnedHostMapping` Mach remap abstraction instead
of adding another raw Mach FFI block. Keep `Vec<u8>` as the portable fallback
until all mutation/clone/serialization users are audited.

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

- [ ] **Step 1: Add a typed aggregate probe red**

Add `DsrExecMapDetailKind::{Mmap, Copy, Icache, Protect, Vvar}` and
`dsr_exec_map_detail(tid, kind, duration_ns, bytes, operations)`. Pin exact
ordinals, uniqueness, real/stub signatures, and five script output rows.

- [ ] **Step 2: Accumulate only in runtime-profile mode**

When `CARRICK_DSR_PROFILE` is present, use monotonic host timing around the
existing operations and accumulate duration, bytes, and operation count in one
exec-local typed struct. Emit five aggregate probes immediately before outer
`ExecImageMapEnd`. When absent, do not read the clock or mutate counters.
Remove the high-frequency lifecycle detail emissions; retain ordinals 15–24 as
reserved ABI values but no longer fire them.

- [ ] **Step 3: Verify the lower-perturbation profile**

Run two signed 220-exec profiles with the same command and reconcile the five
aggregate rows to the outer interval. Require copy to remain first and at least
30% in both runs. Compare guest `fork_exec_p50_us` with the two nested-profile
runs; aggregate profiling must reduce that enabled overhead by at least 10%.
If copy falls below 30%, publish a non-selection and continue with the umbrella
gateway benchmark.

- [ ] **Step 4: Commit**

Use `diagnostics(native): aggregate DSR exec map timing` with exact before/after
profile overhead and component rank.

---

### Task 2: Audit a page-aligned immutable region backing

**Files:**
- Modify: this plan
- Create: `docs/superpowers/specs/2026-07-12-native-prepared-image-backing.md`
- Inspect: `crates/carrick-mem/src/memory.rs`
- Inspect: `crates/carrick-host/src/host_mapping.rs`
- Inspect: native exec/load call sites

- [ ] **Step 1: Inventory representation semantics**

Enumerate every `MemoryRegion` constructor, clone, mutation, serialization,
zero-prefix, relocation, stack, vDSO/vvar, and fork use. Separate immutable ELF
load regions from mutable/runtime regions. Record which callers require deep
copy versus COW.

- [ ] **Step 2: Quantify bytes and false opportunities**

Record per-exec payload bytes and operations from Task 1. For
`perf_fork_exec`, the writable ELF load has only about 6 KiB more `p_memsz`
than `p_filesz`; therefore trailing-zero/BSS trimming cannot be claimed as the
10% solution. Measure rather than infer savings from zero fill.

- [ ] **Step 3: Specify the minimum seam**

The spec must define a portable `RegionBacking` abstraction, `memmap2`-owned
page-aligned immutable backing, mutation/COW semantics, Darwin fixed-address
remap through `carrick-host`, fallback copy behavior, protection transitions,
fork inheritance, and generation invalidation. It must show that preparation
does not merely move the same copy earlier inside the measured workload.

- [ ] **Step 4: Decide implementation readiness**

Proceed only if Task 1 still assigns at least 30% to copy and the spec finds a
single materialization reusable at native map time without stale-file or
fork-coherence shortcuts. Otherwise record the architectural blocker and move
to the gateway benchmark.

---

### Task 3: Implement and gate prepared backing, if authorized by Task 2

**Files:** determined exactly by the Task 2 spec; do not begin from this
umbrella description alone.

- [ ] **Step 1: Write red backing and COW tests**

Cover page alignment, byte identity, zero tail, clone isolation, writable data
after exec, repeated self-exec reset, fork parent/child isolation, executable
generation invalidation, and fallback copy.

- [ ] **Step 2: Implement with existing abstractions**

Add the portable backing seam and extend `OwnedHostMapping` for fixed-address
private remap. No new raw Mach FFI in runtime and no legacy native-executor
optimization work.

- [ ] **Step 3: Run correctness and performance gates**

Use the exact signed workload campaign and fixed promotion gates above. Compare
distinct signed binaries in ABBA order; record hashes, inodes, codesign, host,
power, all raw summary hashes, bootstrap seed, and confidence interval.

- [ ] **Step 4: Promote or restore**

Promote only a full pass. Otherwise restore the copy path in a normal commit
and publish the rejection evidence without weakening thresholds.
