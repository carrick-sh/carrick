# EL1 Data-Abort Entry and Context Preservation Witness

Source revision: `a7d3138df40561d57b61fc88ff040a4de389ec7a` + EL1 fault-entry branch.

## Summary

This increment implements lower-EL data-abort (EC `0x24`) entry through the EL1 vector table and kernel image, full architectural register context preservation, explicit host fallback forwarding, and provenance counter accounting (`fault_taken`).

This is prerequisite entry/forwarding infrastructure, not first-touch or COW service acceptance. The anonymous first-touch red contract (`kernel.el1.anonymous-first-touch`) and its host-exit slope remain red and preserved unchanged.

## Architectural Context and Geometry Invariants

1. **TrapFrame Geometry**:
   - `TrapFrame` appends `pub far: u64` at offset 280 (`0x118`).
   - Total struct size is 288 bytes (`0x120`), which is exactly 16-byte aligned.
   - The stack frame matches the existing reserved stack top offset (`stack_top - 0x120`), proven mechanically safe by `carrick_el1_abi::tests::trap_frame_layout_and_offsets`.

2. **Vector Space Layout & Non-Overlap**:
   - Vector table slots: `0x000` .. `0x800` (2 KiB)
   - Mailbox fstat handler: `0x900` .. `0x940`
   - Mailbox handler: `0xA00` .. `0x1000`
   - Syscall hook (`EL1_VECTOR_HOOK_OFFSET`): `0x1000` .. `0x2000`
   - IRQ hook (`EL0_IRQ_HOOK_OFFSET`): `0x2000` .. `0x3000`
   - Fault hook (`EL0_FAULT_HOOK_OFFSET`): `0x3000` .. `0x4000`
   - Total emitted size fits within `LINUX_EL1_VECTORS_SIZE` (16 KiB = 0x4000) with zero overlap.

3. **Classification & Exception Routing**:
   - Lower-EL Data Abort (`EC = 0x24`, `(esr >> 26) == 0x24`): routed to `EL0_FAULT_HOOK_OFFSET` when EL1 is enabled, or branched directly to `legacy_hvc` when disabled.
   - Non-data-abort exceptions and SVCs with non-matching syndrome: follow standard non-SVC / HVC fallbacks without modifying ELR_EL1.
   - Incidental `x8` values during faults are never dispatched as syscalls.

4. **Context Restoration & Host Fallback**:
   - The emitted fault hook saves all 31 GPRs (x0..x30), SP_EL0, ELR_EL1, SPSR_EL1, ESR_EL1, and FAR_EL1.
   - `dispatch_fault` increments `counters.fault_taken` and returns `Action::Forward`.
   - On `Action::Forward`, the hook restores `FAR_EL1`, `ESR_EL1`, `SPSR_EL1`, `ELR_EL1`, `SP_EL0`, and all GPRs (x0..x30) before jumping to `legacy_hvc`.
   - The host hypervisor trap loop decodes the abort and raises `SIGSEGV` with accurate `si_addr`.

5. **Counters & Provenance Accounting**:
   - `Counters` struct includes `pub fault_taken: AtomicU64` at offset `(1024 + 32) * 8` bytes.
   - Initialized to 0, copied in `copy_snapshot()`, and cleared in `reset_el1_counters()`.

## Fixture and Conformance Contract

- Fixture: `embed-el1-sched` with subcommand `fault-entry`.
  - Sets up register canaries across all GPRs (including arbitrary `x8 = 0x1234_5678_dead_beef`, `x16 = 0xaaaa_bbbb_cccc_dddd`, `x17 = 0x1111_2222_3333_4444`).
  - Triggers write to a `PROT_READ` anonymous page.
  - Catches `SIGSEGV` in `sa_sigaction` handler, asserts `si_addr == target_page`.
  - Upgrades permissions to `PROT_READ | PROT_WRITE` via `mprotect` and returns.
  - Retries store instruction; verifies successful write and verifies all register canaries preserved intact.
- Signed Embed Test: `crates/carrick-embed/tests/el1_sched.rs::el1_memory_fault_entry_preserves_context`.
  - Asserts `measured.result.success()` and `measured.result.stdout_utf8().contains("fault-entry ok")`.
  - Asserts `read_el1_counters().unwrap().fault_taken.load(...) >= 1`.
- Conformance Contract: `conformance-contracts/contracts/el1-fault-entry.toml` registered with `kernel.el1.fault-entry` id.

## Verification Logs

The following commands verify the implementation:

1. `RUSTC_WRAPPER= cargo test -p carrick-el1-abi -p carrick-el1 -p carrick-mem --lib` (19 + 47 + 173 = 239 passed)
2. `RUSTC_WRAPPER= cargo build -p carrick-el1-image` (built bare-metal EL1 image successfully)
3. `RUSTC_WRAPPER= cargo test -p carrick-conformance-contract` (all registry, surface, and contract checks passed)
4. `cargo fmt --all -- --check` (clean formatting across workspace)

Director acceptance will perform signed guest runs on hardware via `./scripts/test-signed.sh carrick-embed el1_memory_fault_entry_preserves_context`.
