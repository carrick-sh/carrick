# Task 2: Runtime Execution Plan And Auxv Page Geometry

## Scope

Implemented runtime execution-plan selection and page-size-aware initial-stack
auxv construction in `carrick-runtime` / `carrick-mem`.

Native Darwin remains hard-gated with `RuntimeError::Unsupported`; this task
does not add a native execution backend.

## Red-First Evidence

### 1. Execution-plan tests

Added `crates/carrick-runtime/src/page_profile.rs` with the red stub
`resolve_execution_plan()` and ran:

```sh
cargo test -p carrick-runtime page_profile::tests --lib
```

Observed failures before implementation:

- `hvf_request_ignores_native_page_geometry` failed with
  `Unsupported("page-profile plan red-first stub")`
- `explicit_hvf_rejects_explicit_native_page_profile` failed because the stub
  error text did not match the expected validation message

### 2. Auxv page-size test

Added `loaded_elf_initial_stack_can_report_16k_pages` in
`crates/carrick-runtime/tests/integration/address_space.rs` and ran:

```sh
cargo test -p carrick-runtime --test integration loaded_elf_initial_stack_can_report_16k_pages
```

Observed the expected red compile failure before implementation:

- no method named `with_linux_initial_stack_page_size` for
  `carrick_runtime::memory::AddressSpace`

## Code Changes

### `crates/carrick-runtime/src/page_profile.rs`

- Added:
  - `ExecutionBackend`
  - `ExecutionPlan`
  - public `PageGeometry`
  - `DEFAULT_LINUX_PAGE_SIZE`
  - `resolve_execution_plan(spec: &RunSpec) -> Result<ExecutionPlan, RuntimeError>`
  - `From<PageGeometry> for NativePageGeometry`
- Behavior:
  - explicit non-native backends reject explicit native page profiles
  - `Auto` / `Hvf` keep the existing 4K Linux page size and ignore native page
    geometry
  - `Native` resolves a Darwin-native page profile and records diagnostics, but
    does not execute

### `crates/carrick-runtime/src/execute.rs`

- Resolved the execution plan at the start of `Runtime::execute`
- Hard-gated `ExecutionBackend::NativeDarwin` with typed
  `RuntimeError::Unsupported`
- Left the current HVF flow on the existing 4K Linux-visible page size

### `crates/carrick-mem/src/memory.rs`

- Added:
  - `AddressSpace::with_linux_initial_stack_page_size`
  - `AddressSpace::with_linux_initial_stack_execfn_page_size`
  - internal `set_linux_auxv_page_size`
- These builders rewrite `AT_PAGESZ`, clear `linux_auxv_image`, and then reuse
  the existing stack-construction path so `/proc/self/auxv` stays in sync with
  the stack auxv image

### Image-builder threading

- `crates/carrick-runtime/src/exec_helpers.rs`
  - threaded `linux_page_size` into `build_run_image_for` and
    `build_run_image_for_execfn`
  - left `build_run_image` on `DEFAULT_LINUX_PAGE_SIZE`
- `crates/carrick-runtime/src/runtime.rs`
  - switched existing HVF boot image builders to the new page-size-aware stack
    helpers with `DEFAULT_LINUX_PAGE_SIZE`
- `crates/carrick-runtime/src/runtime/exec.rs`
  - switched the macOS `execve` image builder to
    `with_linux_initial_stack_execfn_page_size(..., DEFAULT_LINUX_PAGE_SIZE)`
- `crates/carrick-runtime/src/vcpu_loop/mod.rs`
  - switched the non-macOS `execve` image builders to
    `with_linux_initial_stack_page_size(..., DEFAULT_LINUX_PAGE_SIZE)`
- `crates/carrick-runtime/src/lib.rs`
  - exported `page_profile`
  - updated the internal `build_run_image_for_execfn` call site for the new
    `linux_page_size` parameter

### Tests

- Added execution-plan unit tests in `page_profile.rs`
- Added `loaded_elf_initial_stack_can_report_16k_pages`

## Adaptations To The Brief

Two small current-tree adaptations were required:

1. `crates/carrick-runtime/src/runtime/exec.rs` had to be part of the task file
   set because the current macOS `execve` image builder still calls the stack
   constructor directly there.
2. I constrained `NativePageProfileRequest::Linux4k` to 16 KiB hosts. The task
   text says `linux4k-on-16k` means a 4K Linux-visible page size on top of
   16 KiB Darwin mappings; allowing that profile on a non-16 KiB host would not
   match the stated binding rule.

## Verification

Ran the brief's focused verification commands after implementation:

```sh
cargo test -p carrick-runtime page_profile::tests --lib
cargo test -p carrick-runtime --test integration loaded_elf_initial_stack_includes_linux_auxv
cargo test -p carrick-runtime --test integration loaded_elf_initial_stack_can_report_16k_pages
```

Results:

- `page_profile::tests`: 2 passed
- `loaded_elf_initial_stack_includes_linux_auxv`: passed
- `loaded_elf_initial_stack_can_report_16k_pages`: passed

I also ran a narrow `rustfmt --edition 2024` pass on the Task 2 Rust files
before the final verification.

## Self-Review

- Native execution is still gated off at `Runtime::execute` with
  `RuntimeError::Unsupported`
- Existing HVF behavior still advertises 4K Linux pages
- Auxv image reconstruction still stays coupled to stack reconstruction after
  `AT_PAGESZ` updates
- No unrelated workspace dirt was staged into the Task 2 commit

## Commit

- `a17890f1 feat(native): select page geometry for native runs`

## Post-review Fix

### Files changed

- `crates/carrick-runtime/src/page_profile.rs`
- `.superpowers/sdd/task-2-report.md`

### Fixes applied

- `resolve_execution_plan()` now rejects `ExecBackendRequest::Native` when the
  requested guest `Platform` is not host-native for this build, returning a
  typed `RuntimeError::Unsupported` before runtime execution. This closes the
  missing cross-ISA guard for native plan resolution.
- Replaced the silent `From<PageGeometry> for NativePageGeometry` conversion
  with `PageGeometry::native_geometry() -> Option<NativePageGeometry>`, so HVF
  and other non-native plans cannot publish fabricated native geometry.
- Added focused unit coverage for:
  - HVF plans reporting no native geometry
  - native backend rejecting cross-ISA guest plans
  - explicit `linux4k` on the current native AArch64 / 16 KiB host reporting
    Linux `4096` and host `16384`

### Tests run

```sh
cargo test -p carrick-runtime page_profile::tests --lib
```

### Results

- `page_profile::tests`: 4 passed, 0 failed
