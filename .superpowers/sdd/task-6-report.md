# Task 6 Report: Add Guest-Vs-Host Fault Discriminator Probe

**Status:** DONE  
**Date:** 2026-07-09  
**Branch:** `5cd6b745`

Task 6 added only the `fault-discriminator` probe implementation in the
`bench-native` crate and wired that probe from its stub command arm.

## Scope

- Added `bench-native/src/native_exec_probe/fault.rs` (Task 6 implementation).
- Wired `fault-discriminator` in `bench-native/src/native_exec_probe/mod.rs` from
  stub text to `fault_discriminator()`.
- Left `all` still stubbed for Task 7.
- Did not modify production runtime, HVF, HAL, backend selection, or non-native
  crates.

## What changed

### `fault.rs`

The probe now:

- forks a child for a "guest" case and a "host" case (`run_fault_child`),
- installs SIGSEGV/SIGBUS handlers in each child (`fault_handler`),
- sets a process-local `AtomicBool` before triggering `write_volatile` on a null
  pointer,
- returns child exits `90` for the guest-marked run and `91` for the host-marked
  run via the signal handler, and reports pass only when both markers match.

### `mod.rs`

- Added `mod fault;`
- Added `use fault::fault_discriminator;`
- Replaced the stub branch:
  - **before:** `"fault-discriminator" => Err("fault-discriminator probe is implemented in Task 6".to_string())`
  - **after:** `"fault-discriminator" => print_one(fault_discriminator()?)`

## Acceptance command

```bash
cargo run --manifest-path bench-native/Cargo.toml --bin native_exec_probe -- fault-discriminator
```

Observed output:

```text
probe=fault-discriminator status=pass guest_fault_exit=90 host_fault_exit=91
```

## Formatting

Focused formatting:

```bash
cargo fmt --manifest-path bench-native/Cargo.toml
```

## Concerns

- No functional concerns recorded for this task.
