# EL1 Data-Abort Entry and Context Preservation Witness

Source revision: `a7d3138df40561d57b61fc88ff040a4de389ec7a` + Review Rounds 1, 2, & 3 updates.

## Summary

This increment implements lower-EL data-abort (EC `0x24`) entry through the EL1 vector table and kernel image, full architectural register context preservation (all 31 GPRs x0..x30 and SP_EL0), explicit host fallback forwarding, and provenance counter accounting (`fault_taken`).

This is prerequisite entry/forwarding infrastructure, not first-touch or COW service acceptance. The anonymous first-touch red contract (`kernel.el1.anonymous-first-touch`) and its host-exit slope remain red and preserved unchanged.

## Architectural Context and Geometry Invariants

1. **TrapFrame Geometry**:
   - `TrapFrame` appends `pub far: u64` at offset 280 (`0x118`).
   - Total struct size is 288 bytes (`0x120`), which is exactly 16-byte aligned.
   - The stack frame matches the existing reserved stack top offset (`stack_top - 0x120`), proven mechanically safe by `carrick_el1_abi::tests::test_trap_frame_layout`.

2. **Vector Space Layout & Non-Overlap**:
   - Vector table slots: `0x000` .. `0x800` (2 KiB)
   - Mailbox fstat handler: `0x900` .. `0x940`
   - Mailbox handler: `0xA00` .. `0x1000`
   - Syscall hook (`EL1_VECTOR_HOOK_OFFSET`): `0x1000` .. `0x2000`
   - IRQ hook (`EL0_IRQ_HOOK_OFFSET`): `0x2000` .. `0x3000`
   - Fault hook (`EL0_FAULT_HOOK_OFFSET`): `0x3000` .. `0x4000`
   - Total emitted size fits within `LINUX_EL1_VECTORS_SIZE` (16 KiB = 0x4000) with zero overlap.

3. **Classification & Exception Routing**:
   - Exception Class (EC) is decoded as bits [31:26] via `ubfx x16, x16, #26, #6` (`AARCH64_UBFX_X16_X16_26_6_OPCODE` = `0xd35a_7e10`) in generated vectors and `((esr >> 26) & 0x3F)` in Rust.
   - Real kernel entry `carrick_el1_syscall` in `crates/carrick-el1/src/entry.rs` routes directly through `carrick_el1::dispatch_entry`.
   - Lower-EL Data Abort (`EC = 0x24`): routed to `EL0_FAULT_HOOK_OFFSET` when EL1 is enabled, or branched directly to `legacy_hvc` when disabled (`CARRICK_EL1=0`).
   - Non-data-abort exceptions (such as Instruction Abort `EC = 0x20`) and non-matching syndromes follow standard non-SVC / HVC fallbacks without modifying ELR_EL1 or entering EL1 fault hooks.
   - High 32-bit syndrome bits (bits 32..63) are masked out and cannot misdirect classification.
   - Incidental `x8` values during faults (including valid syscall numbers such as `SYS_getpid = 172`) are never dispatched as syscalls.

4. **Context Restoration & Host Fallback**:
   - The emitted fault hook saves all 31 GPRs (x0..x30), ELR_EL1, SPSR_EL1, ESR_EL1, and FAR_EL1.
   - SP_EL0 remains architecturally preserved in the `SP_EL0` system register (since EL1 code operates on `SP_EL1` and never modifies `SP_EL0`).
   - `dispatch_fault` increments `counters.fault_taken` and returns `Action::Forward`.
   - On `Action::Forward`, the hook restores `FAR_EL1`, `ESR_EL1`, `SPSR_EL1`, `ELR_EL1`, and all GPRs (x0..x30) before jumping to `legacy_hvc`.
   - The host hypervisor trap loop decodes the abort and raises `SIGSEGV` with accurate `si_addr`.

5. **Counters & Provenance Accounting**:
   - `Counters` struct includes `pub fault_taken: AtomicU64` at offset `(1024 + 32) * 8` bytes.
   - Initialized to 0 (`Counters::new()`), copied in `copy_snapshot()`, and cleared in `reset_el1_counters()`.
   - `reset_el1_counters()` drops the global pointer and clears the snapshot; `read_el1_counters()` returns `None` after reset until a new carrier initializes counters.

## Fixture and Conformance Contract

- Fixture: `embed-el1-sched` with subcommand `fault-entry` (`target/embed-fixtures/el1-sched-aarch64`, SHA256: `e33f7cae1859cf978a1f1cb0e765deb1a903fbe1f40244a6fa36d321b416eb67`).
  - Maps an anonymous page with `PROT_READ | PROT_WRITE` and touches it to establish backing.
  - Demotes page to `PROT_READ` via `mprotect` to ensure a genuine stage-1 permission fault.
  - Sets up canary values across all 31 GPRs `x0..x30` (including `x8 = 172` / `libc::SYS_getpid` to verify non-dispatch as a syscall) and captures pre-fault SP.
  - Catches `SIGSEGV` in `sa_sigaction` handler with bounds checking (terminates via `libc::_exit` on repeated delivery or failure to avoid infinite retry loops).
  - Asserts `info.si_addr() == target_page`.
  - Upgrades permissions to `PROT_READ | PROT_WRITE` via `mprotect` and returns.
  - Retries store instruction; post-fault register capture saves `x0`/`x1` to stack scratch, reloads `ctx`, captures post-fault SP, saves `x2..x30` directly (preserving all canaries including `x16 = 0x1616161616161616` without clobber), then stores post-fault `x0`/`x1`.
  - Asserts successful write, asserts explicit before/after SP equality and 16-byte alignment, and verifies that all 31 GPR canaries are preserved intact.
- Signed Embed Test: `crates/carrick-embed/tests/el1_sched.rs::el1_memory_fault_entry_preserves_context`.
  - Asserts `reset_el1_counters()` clears stale snapshots.
  - Asserts fixture `fault-entry` succeeds and stdout contains `"fault-entry ok"`.
  - Under enabled EL1 (`CARRICK_EL1!=0`): asserts `fault_taken >= 1`.
  - Under disabled EL1 control (`CARRICK_EL1=0`): asserts `fault_taken == 0`.
- Conformance Contract: `conformance-contracts/contracts/el1-fault-entry.toml` registered with `kernel.el1.fault-entry` id. Under unresolved bindings, `docker` is recorded as pending signed acceptance.

## Red-First Witness and Verification

A real semantic red witness was demonstrated by disabling fault classification in `dispatch_entry`.
- Source delta preserved in: `docs/perf-results/2026-09-26-el1-fault-entry/red-source.diff` (omits fault classification branch in `dispatch_entry`).
- Raw failure log preserved in: `docs/perf-results/2026-09-26-el1-fault-entry/red-test.log` (command exited with code 101, failing `test_dispatch_entry_routes_fault_with_high_bits_and_arbitrary_x8` due to `left: 0, right: 1` on `counters.fault_taken`; Cargo stopped with error before executing subsequent `carrick-mem` unit tests).
- Restoring the implementation yielded green across all 244 unit tests.

Verification commands:

1. `RUSTC_WRAPPER= cargo test -p carrick-el1-abi -p carrick-el1 -p carrick-mem --lib` (20 + 50 + 174 = 244 passed, exit code 0)
2. `RUSTC_WRAPPER= cargo build -p carrick-el1-image` (bare-metal EL1 image built successfully, exit code 0)
3. `RUSTC_WRAPPER= cargo test -p carrick-conformance-contract` (contract, surface, and inventory checks passed, exit code 0)
4. `cargo fmt --all -- --check` (clean formatting, exit code 0)
5. `RUSTC_WRAPPER= scripts/build-embed-el1-sched.sh` (static aarch64 musl fixture built with zero warnings, exit code 0)
6. `RUSTC_WRAPPER= cargo test -p carrick-embed --test el1_sched --no-run` (embed test executable compiled successfully, exit code 0)

Director acceptance will perform signed guest runs on hardware via `./scripts/test-signed.sh carrick-embed el1_memory_fault_entry_preserves_context`.
