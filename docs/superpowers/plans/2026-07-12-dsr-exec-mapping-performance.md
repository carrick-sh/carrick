# DSR exec mapping performance implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` task-by-task. Steps use checkbox (`- [ ]`)
> syntax for durable progress tracking.

**Goal:** Remove DSR-only instruction-cache publication work from original
guest mappings that are deliberately non-executable, and promote the change
only if both image-map and outer exec p50 improve by at least 10%.

**Architecture:** Preserve the existing Darwin `mmap`/copy/`mprotect` mapping
sequence and every Linux-visible address-space semantic. Add one explicit
policy predicate: original or injected guest bytes need host I-cache
publication only when the selected native code mode can execute those bytes.
DSR maps executable guest regions read-only and executes only translated
`MAP_JIT` cache bytes, whose writer already owns its own publication. Therefore
the two source-mapping `carrick_native_clear_icache` calls are unnecessary in
DSR mode. Non-DSR behavior remains mechanically unchanged; it is not a
performance target or comparison lane.

**Evidence authority:**
[`native-dsr-exec-subphases-v1.jsonl`](../../perf-results/native-dsr-exec-subphases-v1.jsonl)
contains two complete 220-exec runs. Image mapping is stable at 61.7% and 61.8%
of outer time, with p50 1.055 ms and 1.007 ms. Cache reset is second at 26.7%
and 27.0%; every other named phase is below 6%.

**Acceptance:** correctness is green; both signed binaries are distinct; the
candidate's `exec-image-map` and outer `exec-reset` p50 are each at least 10%
below baseline across 220 matching samples; the profile completes naturally
with zero drops/incomplete pairs and every subphase sum remains bounded by its
outer interval. If either timing gate fails, restore the two DSR flushes and
record the experiment as rejected rather than weakening the threshold.

---

### Task 1: Pin the DSR source-mapping publication policy red

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Test: `crates/carrick-runtime/src/native_darwin.rs`

**Interfaces:**
- Consumes: `carrick_spec::NativeCodeModeRequest` and the mapping's executable
  bit.
- Produces: `native_mapping_needs_icache_publication(executable, mode) -> bool`.

- [ ] **Step 1: Add the policy test**

```rust
#[test]
fn dsr_source_mappings_do_not_publish_host_icache() {
    assert!(!native_mapping_needs_icache_publication(
        true,
        carrick_spec::NativeCodeModeRequest::Dsr,
    ));
    assert!(!native_mapping_needs_icache_publication(
        false,
        carrick_spec::NativeCodeModeRequest::Dsr,
    ));
    assert!(native_mapping_needs_icache_publication(
        true,
        carrick_spec::NativeCodeModeRequest::Brk,
    ));
}
```

- [ ] **Step 2: Run red**

```bash
cargo test -p carrick-runtime \
  dsr_source_mappings_do_not_publish_host_icache --lib -- --nocapture
```

Expected: compilation fails because the policy function does not exist.

- [ ] **Step 3: Commit only the red test**

Use `test(native): pin DSR source mapping publication` with the red command in
the body.

---

### Task 2: Skip I-cache publication for non-executable DSR source bytes

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin.rs`

**Interfaces:**
- Consumes: the Task 1 predicate.
- Produces: no `carrick_native_clear_icache` call from `map_region` or
  `map_bytes_region` when mode is DSR.

- [ ] **Step 1: Implement the narrow predicate**

```rust
const fn native_mapping_needs_icache_publication(
    executable: bool,
    mode: carrick_spec::NativeCodeModeRequest,
) -> bool {
    executable && !matches!(mode, carrick_spec::NativeCodeModeRequest::Dsr)
}
```

Use it at both current cache-clear call sites. Do not change `mmap`, byte copy,
final protection, vDSO-vvar relocation, translated-cache publication, or the
legacy patch path.

- [ ] **Step 2: Run mapping and DSR correctness**

```bash
cargo test -p carrick-runtime \
  dsr_source_mappings_do_not_publish_host_icache --lib -- --nocapture
cargo test -p carrick-runtime \
  native16k_dsr_exec_protection_preserves_linux_syscall_words --lib -- --nocapture
cargo test -p carrick-runtime dsr_generation --lib -- --nocapture
cargo test -p carrick-runtime dsr_signal_fault --lib -- --nocapture
cargo clippy -p carrick-runtime --lib -- -D warnings
```

- [ ] **Step 3: Commit the candidate**

Use `perf(native): skip DSR source icache publication`. The body must explain
why DSR source mappings are never instruction-fetch targets and name the tests.

---

### Task 3: Prove signed static/PIE and lifecycle correctness

**Files:**
- No source changes unless a real correctness failure is found.

- [ ] **Step 1: Build and verify the signed candidate**

```bash
just build
otool -l target/release/carrick | grep -A2 __dof_carrick
```

- [ ] **Step 2: Run direct signed workloads**

Use the already-built, provenance-recorded workload artifacts; do not rebuild
them between baseline and candidate. Run the Rust static PIE fork/exec probe,
Rust glibc dynamic PIE trap-floor probe, and the minimized Go PIE fixture:

```bash
CARRICK_RUN_ID=dsr-icache-static timeout 60 target/release/carrick run-elf \
  --raw --exec-backend native --native-page-profile native16k \
  --native-code-mode dsr \
  conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/perf_fork_exec
CARRICK_RUN_ID=dsr-icache-rust-gnu timeout 60 target/release/carrick run-elf \
  --raw --exec-backend native --native-page-profile native16k \
  --native-code-mode dsr \
  conformance-probes/target/native-pie/aarch64-unknown-linux-gnu/release/perf_trap_floor
CARRICK_RUN_ID=dsr-icache-go-pie timeout 60 target/release/carrick run-elf \
  --raw --exec-backend native --native-page-profile native16k \
  --native-code-mode dsr target/dsr-go-pie
```

Require exit zero, the full `perf_fork_exec` iteration count, the trap-floor
summary, and `go-pie-ok`. Record SHA-256 and `file` output for each artifact.
The Go artifact is a dynamic PIE, so this is not evidence for the eventual Go
static-executable requirement.

Run direct V8 independently:

```bash
CARRICK_RUN_ID=dsr-icache-v8 timeout 60 target/release/carrick run \
  --name dsr-icache-v8 --max-traps 18446744073709551615 \
  --raw --fs host --entrypoint /opt/nodejs-conformance/bin/node24 \
  --exec-backend native --native-page-profile native16k \
  --native-code-mode dsr \
  localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0 \
  /opt/nodejs-conformance/fixtures/v8-smoke.js
```

Then run the two signed focused lifecycle tests from the repository root:

```bash
cargo test -p carrick-cli --test conformance \
  native_conformance_dsr_exec_from_non_leader_replaces_image \
  -- --nocapture --test-threads=1
cargo test -p carrick-cli --test conformance \
  native_conformance_dsr_vfork_exec_from_sibling_completes \
  -- --nocapture --test-threads=1
```

Stamp every direct run and use `scripts/sudo/kill.sh <run-id>` only if its run
does not exit naturally. Expected: all retain their success markers and exit
zero.

- [ ] **Step 3: Confirm the semantic-oracle boundary**

Do not claim a new Linux syscall-shape result from this experiment: it changes
only Darwin host I-cache maintenance after bytes have already been copied. The
workload success markers remain previously established Linux-oracle outputs;
if any marker changes, run that exact artifact under native arm64 Linux in a
separate Docker-only phase before diagnosing Carrick.

---

### Task 4: Measure and decide

**Files:**
- Create: `docs/perf-results/native-dsr-exec-icache-v1.jsonl`
- Modify: `docs/native-dsr-dtrace-profile.md`
- Modify: `docs/superpowers/plans/2026-07-12-dsr-exec-mapping-performance.md`
- Modify: `docs/superpowers/plans/2026-07-12-dsr-profile-driven-performance.md`

- [ ] **Step 1: Freeze signed before/after binaries**

The host sudoers rule authorizes only this worktree's canonical
`target/release/carrick`, so trace each build from that path rather than trying
to execute a frozen copy. Before replacing it, copy the signed baseline to
`target/perf/dsr-exec-icache/baseline-carrick`; after the candidate build, copy
the candidate to `target/perf/dsr-exec-icache/candidate-carrick`. Record commit,
SHA-256, inode, codesign, host, and power for both and reject identical hashes.
The baseline release binary must be built from the red-test commit; tests do
not alter release code, so an already-signed binary from its runtime parent is
valid only when its hash and source commit are recorded explicitly.

- [ ] **Step 2: Run matching 220-exec profiles**

Use the exact `perf_fork_exec` `dsr-fork` command from the selection evidence.
Require `target_exit_reason=1`, 220 samples for outer and every subphase, zero
drops/incomplete pairs, and exact per-pid/tid reconciliation. Store compact
before/after summaries plus source-profile SHA-256 values in
`native-dsr-exec-icache-v1.jsonl`.

- [ ] **Step 3: Apply the fixed decision**

Pass only when:

- candidate `exec-image-map` p50 is at most 90% of baseline;
- candidate outer `exec-reset` p50 is at most 90% of baseline;
- every correctness gate in Task 3 is green; and
- no other subphase regresses enough to erase the outer improvement.

If the decision passes, promote. If it fails, restore the two calls in a normal
follow-up commit and publish the rejection evidence; do not move the 10% rule.

- [ ] **Step 4: Commit the decision**

Use `perf(native): promote DSR exec mapping` for a pass or
`docs(native): reject DSR exec icache experiment` for a failure. Include exact
old/new p50/p95, ratios, profile SHAs, and signed workload results.
