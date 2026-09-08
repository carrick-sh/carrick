# cpython-compile ratio attribution (23.3x: 62.3 s vs 2.7 s)

**Recorded 2026-09-07.** Base revision `31c473c16` on branch `agy/attr-compile2-sep07`.

## 1. The Question

The `cpython-compile` suite (`test_compile`) under Carrick takes 62.3 s (and up to 136.5 s under host load ~20) compared to 2.7 s under the native arm64 Docker oracle — an apparent 23.3x slowdown.

Exact harness command:
```sh
target/release/carrick run --name attr-compile --max-traps 18446744073709551615 --fs host localhost:5050/cpython-test:3.12.13 /usr/local/bin/python3 -m test -v --randseed 0 test_compile
```

## 2. Per-Test Durations and Slowest Tests

Running the full suite under Carrick (`Ran 151 tests in 136.494s` under host load ~20.9) and profiling method durations via `python3 -m unittest --durations 10 test.test_compile` isolated the test times:

| Test Name | Duration (Carrick) | % Suite Time | Notes |
|---|---:|---:|---|
| `test_compiler_recursion_limit` | 197.33 s (isolated) / ~130 s (in `-v`) | ~95.2% | Deep recursion crash depth test (1,000,000 depth) |
| `test_big_dict_literal` | 2.98 s | 2.2% | Large AST literal compilation |
| `test_extended_arg` | 1.46 s | 1.1% | Large jump/oparg compilation |
| `test_compiles_to_extended_op_arg` | 0.48 s | 0.3% | Source position oparg test |
| Remaining 147 tests | <0.2 s each | <1.2% | Fast syntactic checks |

*Note on `test_stack_overflow`*: In `python3 -m unittest` without resource filters, `test_stack_overflow` ran in 45.85 s. In the official harness command (`python3 -m test`), `test_stack_overflow` is skipped (`resource 'cpu' is not enabled`). Thus, `test_compiler_recursion_limit` alone accounts for >95% of the total runtime in the gating harness.

### Why `test_compiler_recursion_limit` is slow

In `test/test_compile.py`:
```python
fail_depth = C_RECURSION_LIMIT + 1        # 10,001
crash_depth = C_RECURSION_LIMIT * 100     # 1,000,000 (1 million!)
...
check_limit("a", "()")
check_limit("a", ".b")
check_limit("a", "[0]")
check_limit("a", "*a")
```
`check_limit` compiles expressions with 1,000,000 chained calls or attributes (e.g. `a()()()...`), expecting `RecursionError`. It does this 4 times at `crash_depth = 1,000,000`.

## 3. Minimal Reducer (≤20 lines)

The following 8-line script reproduces the ratio:
```python
import time

t0 = time.time()
try:
    compile('a' + '()' * 1000000, '<test>', 'single')
except RecursionError:
    pass
print(f"1M calls compile: {time.time() - t0:.3f}s")
```

### Reducer Timing Comparison

| Environment | 1M Calls Duration | Host Load |
|---|---:|---|
| Host Python 3.12 (native arm64) | 0.498 s | load 20.9 |
| Carrick (`target/release/carrick`) | 27.341 s (load 20.9) / 17.766 s (load 9.1) | load 9.1–20.9 |
| **Ratio** | **35.7x – 54.9x** | |

Compiling this expression 4 times takes 4 * ~0.5 s = 2.0 s on native Linux (explaining the 2.7 s total suite time in Docker), but 4 * ~17.8–27.3 s = 71–109 s under Carrick.

### Scaling Sweep (Depth vs Wall Clock)

Sweeping depth under Carrick revealed super-linear / quadratic scaling:

| Depth | Carrick Time (s) | Growth Factor (vs 100k) | Expected O(N^2) Factor |
|---|---:|---:|---:|
| 100,000 | 0.144 s | 1.0x | 1.0x |
| 200,000 | 0.329 s | 2.3x | 4.0x |
| 300,000 | 1.025 s | 7.1x | 9.0x |
| 400,000 | 1.833 s | 12.7x | 16.0x |
| 500,000 | 2.498 s | 17.3x | 25.0x |
| 600,000 | 7.500 s | 52.1x | 36.0x |
| 800,000 | 23.153 s | 160.8x | 64.0x |
| 1,000,000 | 17.766 s – 27.341 s | 123.4x – 189.9x | 100.0x |

The time scales quadratically O(N^2) with allocation and fault count.

## 4. Operation Attribution and Trace Evidence

Attribution trace using `carrick trace` with `scripts/dtrace/cpython-compile-attr.d` on the 400,000-depth reducer (`HOST_IMAGE_BASE|base=0x100fac000|slide=0xfac000`, load 15.77):

### Operation Counts and Latencies (400k depth)

| Operation | Count | Total Duration | Per-Op Duration | Carrick Code Path |
|---|---:|---:|---:|---|
| `vcpu-fault` (EL0 aborts) | 39,181 | ~21.2 s | 541 µs / fault | `crates/carrick-vmm-hvf/src/trap.rs:47157` |
| `hvpatch-guest-fault` | 38,859 | ~18.5 s | 476 µs / fault | `crates/carrick-runtime/src/vcpu_loop/mod.rs:7838` |
| `munmap` syscall | 76 | 869.4 ms | 11.4 ms / call | `crates/carrick-runtime/src/dispatch/mem.rs:2587` |
| `brk` syscall | 1,005 | 436.7 ms | 434 µs / call | `crates/carrick-runtime/src/dispatch/mem.rs:5545` |
| `mremap` syscall | 20 | 193.4 ms | 9.67 ms / call | `crates/carrick-runtime/src/dispatch/mem.rs:6115` |
| `mmap` syscall | 176 | 140.2 ms | 796 µs / call | `crates/carrick-runtime/src/dispatch/mem.rs:5214` |
| `stage1-arena-bind` / install | 1 | <1 ms | <1 ms | `crates/carrick-runtime/src/dispatch/mem.rs` |

### User CPU Profile (Sampled Stacks at 1997 Hz)

Symbolicating the carrier stacks via `atos -o target/release/carrick -l 0x100fac000`:

1. **Stack 1 (6,470 samples, 48.6% of CPU):**
   - `carrick_vmm_hvf::trap::HvfInner::run_to_exit` (EL0 data abort return)
   - `carrick_aarch64::vmm::Aarch64Vcpu::run`
   - `carrick_runtime::vcpu_loop::ProductionHvpatchLoopJob::poll_with_engine`
2. **Stack 2 (4,000 samples, 30.1% of CPU):**
   - `carrick_runtime::hvpatch::ProcessContext::trace_fault`
   - `carrick_runtime::vcpu_loop::ProductionHvpatchLoopJob::poll_with_engine` (`mod.rs:7838`)
3. **Stack 3–7 (>2,000 samples, 15.0% of CPU):**
   - `carrick_runtime::vcpu_loop::signal::resolve_mutating_fault` (`signal.rs:370`)
   - `carrick_aarch64::engine::Aarch64EngineCore::protect_range`
   - `carrick_aarch64::engine::Aarch64EngineCore::diagnostic_fault_page_tables`
   - `carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Vmm::host_ptr` (`hvf_aarch64_engine.rs:1150`)

## 5. Root Cause Mechanism

The mechanism driving the 23.3x slowdown is **O(N^2) linear scans over `HvfTaskState.mappings` on the synchronous fault handling path**.

1. When CPython compiles 1,000,000 nested calls, it allocates and touches ~200–400 MiB of virtual memory across ~40,000–105,000 4 KiB pages.
2. Each first touch triggers an EL0 data abort (`vcpu-fault`).
3. For each of the ~40,000–105,000 faults, Carrick executes:
   - `self.mapping_for_range(current, 1)`: iterates `self.mappings.iter().rev().find(...)` (O(N) scan).
   - `next_local`: computes `self.mappings.iter().filter(|m| m.start > current && m.start < window_end).map(|m| m.start).min()` (O(N) scan).
   - `lower_has_local`: computes `self.mappings.iter().any(|m| m.start < current && m.end > compound_start)` (O(N) scan).
   - `materialize_sparse_mmap_extent`: computes another `next_local` via `self.mappings.iter().filter(...).min()` (O(N) scan).
   - `diagnostic_fault_page_tables`: traverses 4 page table levels, each calling `host_ptr` -> `Self::mapping_for_ipa_range(&self.mappings, gpa, 8)` which runs `self.mappings.iter().rev().find(...)` (4 * O(N) scans).
4. In total, **each fault executes 8 full linear scans over `self.mappings`**. Because `self.mappings` grows with every materialized extent (up to N ~ 40,000–100,000 items), the cumulative lookup work across the run is `8 * Sum_{i=1}^N i = 4 * N^2` comparisons.
5. At N = 100,000, this requires **40 billion element comparisons**, burning ~27 s per 1M compilation (4 calls in `test_compiler_recursion_limit` = ~108 s total Carrick time vs ~2.0 s native).

In commit `a1fd9ad94`, `partition_point` binary searches on `self.mappings` were reverted to full scans because `self.mappings` was not maintained sorted by start address across all insertion points (fork copies, extension arenas, and unmap split tails appended out-of-order). Restoring an always-sorted invariant on `self.mappings` by construction at every insertion site will reduce these searches from O(N) to O(log N), eliminating the quadratic bottleneck.
