# Native synchronous syscall slice

This is a non-product experiment, outside the workspace's product graph. It runs
an independently authored static Linux AArch64 ELF through an explicit instruction
whitelist, a macOS JIT gateway, and the current public kernel dispatcher. It does
not run LTP inotify09, libc, Node, Go or Python. Do not run untrusted ELF files.

The purpose is to test whether actual guest execution can approach Linux's
inotify cost after removing HVF interception, while exposing compute and memory
translation costs separately. See the [results](../../docs/perf-results/2026-09-21-syscall-floor/native-memory/README.md).

From the repository root:

```sh
sh experiments/native-syscall-slice/fixtures/build.sh
RUSTC_WRAPPER= CARGO_TARGET_DIR=target cargo test --manifest-path experiments/native-syscall-slice/Cargo.toml --tests
RUSTC_WRAPPER= CARGO_TARGET_DIR=target cargo build --release --manifest-path experiments/native-syscall-slice/Cargo.toml
codesign --force --sign - --identifier sh.carrick.native-slice target/release/native-syscall-slice
CARRICK_RUN_ID=native-slice-local target/release/native-syscall-slice target/lease-cost/native-slice/fixtures/watch-2-128
```

Output is ten 56-byte binary guest records on stdout and a diagnostic JSON
receipt on stderr. `measure.py` parses records, discards the first as warmup,
checks queue state, preserves raw streams and runs native, frozen HVF, then Docker
serially. Its pinned images and frozen HVF path are investigation-specific.
`NSLICE_VARIANT` must be unique for each cohort. `NSLICE_NATIVE` optionally selects
a preserved native control executable; its hash is recorded and checked for stability. The ELF linker is rust-lld;
the macOS host binary retains the normal Apple linker.

`--features allocation-metrics` builds a separate *instrumented* variant. Preserve
the timing binary before building it. Its allocator has a positive control and
counts each guest operation window. `CARRICK_OBSERVATION_OUTPUT` plus
`CARRICK_OBSERVATION_SOURCE` writes a typed, deliberately incomplete contract
observation for the invalid-fd fixture. No timing claim may use that binary.

## Boundaries

- SVC enters the current policy/interceptor/observer preparation and semantic
  dispatch. The host never fabricates the loop's syscall arguments or results.
- The public kernel owns the exact task/thread/MM lease. Each native segment now
  holds a `NativeExecution` scope; the existing checkpoint returns to Rust and
  drops that scope before semantic dispatch. The scope owns its census running
  flag and a request-only interrupt endpoint, without holding mutation exclusion.
  Pending carrier control work stops this research runner for lack of a service.
  Resume checks validate its identity without creating a VMA snapshot. This identity grants no memory
  access or code publication rights.
- The experimental memory object exclusively owns ELF backing, permissions and
  code generation. No guest VA becomes a host pointer or the physical SP. The
  same object supplies syscall buffers and native or emulated loads/stores. It is **not**
  the unified carrier's frame inventory, COW or foreign-write transport.
- Code publication is tied to that private memory identity and generation.
  Mutations, unmap and permission changes revoke it before resume. RX writes,
  W+X segments, wrong publications and unsupported instructions fail closed.
- Arithmetic and forward branches execute natively. Backward edges have a
  256-edge countdown; SVC and other callbacks also check and reset it. A maximum
  4096-word code image bounds guest-only work between callbacks. This is an
  execution checkpoint, not a blocking-wait poll or a scheduler implementation.
- Guest SP/TLS and Darwin-reserved registers have separate snapshot storage.
  Unsupported direct uses of reserved registers are rejected. The gateway saves
  all SIMD state, flags and available guest registers across callbacks.
- Scalar 32/64-bit loads/stores use native whole-access bounds checks for one
  exclusively owned non-executable RW data region. Backing pointers are borrowed
  only during execution and refreshed after each callback; permission/generation
  changes revoke resume. Misses use the checked Rust path. This is private ELF
  backing, not a current-carrier memory grant, COW or a general mapping cache.
- Null host signal/timer bridges, no signal handlers, no blocking continuations,
  no clone/exec/mprotect syscall support, no COW or concurrent scheduling. A
  deliverable non-ignored guest signal or unsupported outcome stops execution.
  The real scheduler's migratable register-state publication is not integrated.

All new source here is MIT OR Apache-2.0. No third-party implementation code was
copied. The old DSR planner remains a separate recovered research artifact; its
identity/bias memory model and native-process fork model were not restored.

The current scope integration and its functional receipts are recorded in
[native-scope](../../docs/perf-results/2026-09-21-syscall-floor/native-scope/README.md).
The `scoped_execution` integration test executes all five unchanged ELF controls
at 1/8/32/128 and checks 200 guest records plus syscall/completion counts. These
are debug functional runs, and do not update the earlier release timing results.
