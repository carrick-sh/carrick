# Native DSR Emission Performance Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** reduce native DSR code-churn wall time by reducing the measured block
emission cost without weakening generation guards, recovery maps, direct-link
publication, fork behavior, or instruction coverage.

**Architecture:** preserve the current `BlockPlan` and emitted-code contracts.
First separate bad64-dependent rewrite work, dynasmrt assembly/finalization,
byte reshaping, MAP_JIT copy/publication, and write-window batching. Select one
change only from stable release measurements; use dynasmrt's supported capacity
and buffer APIs or direct byte copying before introducing custom assembly
storage.

**Tech Stack:** Rust 1.96, `bad64` 0.12, `dynasmrt` 5.0,
`pthread_jit_write_protect_np`, signed native DSR fixtures.

## Global Constraints

- Do not read Linux kernel or other GPL implementation source.
- Disabled diagnostics must not allocate, format, lock, or read clocks.
- Preserve the exact `InstructionMap`, `RecoveryEntry`, `DirectLink`, generation
  guard, W^X, I-cache publication, and typed-error contracts.
- Do not change instruction coverage from an emission microbenchmark alone.
- A candidate must improve the selected emit component by at least 10% and
  improve JIT rewrite or concurrent-first-publication wall time with a 95%
  bootstrap upper ratio below 1.0.
- Direct V8 and batch-16 syscall-floor upper ratios must remain at or below
  1.01.

---

### Task 1: Attribute the emission pipeline

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/emit.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/cache.rs`
- Create: `docs/perf-results/native-dsr-emission-components-v1.jsonl`

**Interfaces:**
- Consumes: representative copy, direct, indirect, virtual-register, and
  generation-guarded `BlockPlan` values.
- Produces: per-block release distributions for rewrite/decode, dynasm build,
  dynasm finalize, byte-to-word reshape, MAP_JIT copy/publish, and 1/4/16-block
  write-window shapes.

- [ ] **Step 1: Write red benchmark shape and output tests**

Add ignored release benchmarks with stable machine keys and tests that reject
missing, non-finite, or non-positive component values. Pass every result through
`black_box` and keep benchmark state thread-local.

- [ ] **Step 2: Implement exact component benchmarks**

Measure current production primitives, including `bad64::decode` where emit
rewrites operands, `VecAssembler::new`/emission/`finalize`, the current
`Vec<u8>` to `Vec<u32>` reshape, and `CacheWriter::write_words`/`publish`.
Separately benchmark `VecAssembler::new_with_capacity`, direct byte copying,
and 1/4/16 logical blocks per MAP_JIT write window without changing production.

- [ ] **Step 3: Collect two independent 30-process campaigns**

Use release tests, 20,000 sampled batches where practical, AC power, and the
same binary hash in both campaigns. Check in raw arrays, p50/p95/min/IQR,
binary/host provenance, and fixture block shapes.

- [ ] **Step 4: Select only a stable component and candidate**

Require the current component to explain at least 20% of the 3.716 ms JIT emit
baseline in both campaigns and the candidate primitive to improve that
component by at least 20%. If no component qualifies, record emission as
resolved below the next pole and stop.

---

### Task 2: Implement the selected Rust-ecosystem candidate

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/emit.rs`
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/cache.rs`
- Test: `crates/carrick-runtime/src/native_darwin/dsr/emit.rs`
- Test: `crates/carrick-runtime/src/native_darwin/dsr/cache.rs`

**Interfaces:**
- Consumes: the Task 1 selected component and one measured candidate.
- Produces: the same `EmittedBlock` and `PublishedCode` contracts with less
  measured emission work.

- [ ] **Step 1: Write the mechanism oracle red**

For direct bytes, require byte-exact AArch64 publication without an intermediate
word vector. For capacity reuse, require identical labels, relocations, and
recovery maps over repeated mixed blocks. For batching, require failure-atomic
generation checks and no executable visibility before the whole batch commits.

- [ ] **Step 2: Implement only the selected candidate**

Prefer `VecAssembler::new_with_capacity`, `reserve_ops`, `drain`, and slice copy
APIs already supplied by Rust/dynasmrt. Do not add a custom assembler, arena,
or lock-free reclamation scheme.

- [ ] **Step 3: Run focused correctness**

Run all emit/cache unit tests, the full serial DSR oracle module, JIT rewrite,
concurrent first publication, static/dynamic PIE, and Go PIE. Re-run the
red-first test against the pre-candidate file when practical.

---

### Task 3: Promote or reject the candidate

**Files:**
- Modify: `crates/carrick-cli/tests/dsr_trace_overhead.rs`
- Create: `docs/perf-results/native-dsr-emission-candidate-v1.jsonl`
- Modify: `docs/native-dsr-dtrace-profile.md`
- Modify: `docs/dynamic-syscall-rewriter.md`
- Modify: `docs/superpowers/plans/2026-07-12-dsr-profile-driven-performance.md`

**Interfaces:**
- Consumes: frozen signed baseline/candidate binaries and Task 1 evidence.
- Produces: a promoted improvement or an evidence-backed stop record.

- [ ] **Step 1: Freeze binaries and run fixed-order ABBA**

Record commit, SHA-256, inode, and CDHash. Use at least 30 JIT-rewrite and 30
concurrent-first-publication samples per role with 10,000 seeded bootstrap
median-ratio resamples.

- [ ] **Step 2: Apply performance thresholds**

Require at least 10% emit-component improvement, an improved JIT or concurrent
wall interval with upper ratio below 1.0, and no more than 1% regression in the
other churn lane, direct V8, or batch-16 syscall floor.

- [ ] **Step 3: Run full verification and record the decision**

Run `RUST_TEST_THREADS=1 just ci`, retain exact correctness/workload evidence,
and promote only if every threshold passes. Otherwise restore the candidate and
check in the rejected experiment.
