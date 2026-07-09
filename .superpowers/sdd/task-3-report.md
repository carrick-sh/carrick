# Task 3 Report: Executable-Memory Probe

## Scope
Implement only Task 3 from the no-VMM native feasibility campaign:
- Add `bench-native/src/native_exec_probe/execmem.rs`
- Wire `execmem` in `bench-native/src/native_exec_probe/mod.rs`
- Do not touch other probes’ behavior or runtime/HVF/HAL/backends.

## Implemented
- Added `execmem()` in `bench-native/src/native_exec_probe/execmem.rs` using the exact probe shape from the brief.
  - `sysconf(_SC_PAGESIZE)` check
  - `mmap` with `PROT_READ|PROT_WRITE`
  - emit `mov w0, #42; ret` bytes into the page
  - `mprotect` to `PROT_READ|PROT_EXEC`
  - transmute to function pointer and execute
  - return report fields `mode=rw-to-rx` and `return=<value>`
  - emit `mmap_errno`/`mprotect_errno` on failure
- Wired `native_exec_probe` CLI dispatch in `mod.rs`:
  - `execmem` now calls the real probe and reports via `print_one`.
  - `brk-trap`, `branch-gateway`, `fault-discriminator`, and `all` remain stubbed/placeholder text as required.

## Acceptance
- Ran:
  - `cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- execmem`
  - Output observed:
    - `probe=execmem status=pass mode=rw-to-rx return=42`
- Ran focused formatting:
  - `cargo fmt --manifest-path bench-native/Cargo.toml --all`

## Notes
- No production runtime, HVF, HAL, backend selection, or cross-ISA changes were made.
- Tasks 4–8 are intentionally untouched.
