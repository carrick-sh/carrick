# Task 1 Report: Add the native_exec_probe harness (Phase 0)

## Status

Task 1 is implemented as specified.

## Files Changed

- `bench-native/Cargo.toml`
  - Added `native_exec_probe` binary entry:
    - `name = "native_exec_probe"`
    - `path = "src/bin/native_exec_probe.rs"`
- `bench-native/src/bin/native_exec_probe.rs`
  - Added crate entrypoint that calls `native_exec_probe::run_from_env()`.
  - Returns exit code `0` on success, `2` on error and prints `native_exec_probe: ...` to stderr.
- `bench-native/src/native_exec_probe/mod.rs`
  - Added argument parsing for:
    - `page-size`, `fixed-map`, `execmem`, `brk-trap`, `branch-gateway`, `fault-discriminator`, `all`
  - Implemented stubs for probe commands (deferred to later tasks) and usage error path.
- `bench-native/src/native_exec_probe/report.rs`
  - Added `Status` enum (`Pass`, `Fail`, `Skip`), `ProbeReport` structure, and `shell_escape` formatting helper.
  - Matched the exact Task 1 code shapes in the brief.

## Validation

- Focused task command:
  - `cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe`
  - Result: non-zero exit with usage output:
    - `native_exec_probe: usage: native_exec_probe page-size|fixed-map|execmem|brk-trap|branch-gateway|fault-discriminator|all`
  - Exit code observed: `2`.
- Formatting:
  - `cargo fmt --manifest-path /Volumes/CaseSensitive/carrick/bench-native/Cargo.toml --all`
  - Completed with no formatting diffs.

## Concerns

- The new probe/report module intentionally contains unused functions/types in this task (`print_one`, `errno`, `ProbeReport`, etc.) because later tasks wire in real probes and output paths; Task 1 expects these placeholders to exist now.

## Post-review Fix (Task 1 warning cleanup)

- Added `#![allow(dead_code)]` to:
  - `bench-native/src/native_exec_probe/mod.rs`
  - `bench-native/src/native_exec_probe/report.rs`
- Scope is intentionally narrow to Task 1 transitional scaffolding; all Task 1 behavior and probe entrypoint contracts remain unchanged.
- This removes the 7 transitional `dead_code` warnings without adding probe implementations.

## Task 1 Warning-Fix Validation

- `cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe`
  - Exit code: `2`
  - Output is now only:
    - `native_exec_probe: usage: native_exec_probe page-size|fixed-map|execmem|brk-trap|branch-gateway|fault-discriminator|all`
- `cargo fmt --manifest-path /Volumes/CaseSensitive/carrick/bench-native/Cargo.toml --all`
  - No formatting changes required.
