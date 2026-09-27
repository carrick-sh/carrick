# EL1 data-abort entry implementation plan

> For agentic workers: use the executing-plans skill task by task. The director owns signed guest verification and integration.

**Goal:** Preserve and route EL0 data-abort state through the EL1 image, with an explicit host fallback and an actual signed entry witness, enabling the subsequent in-guest memory service.

**Architecture:** Extend the existing trap-frame/vector mechanism; do not create a second fault or memory policy. Route only lower-EL data aborts to a typed EL1 entry. Until the memory service lands, restore the original architectural fault state and forward through the existing host fault transport. Kernel exceptions remain distinct.

**Tech stack:** Rust, generated AArch64 vector instructions, existing no_std EL1 image, signed embed fixtures.

**Spec:** docs/superpowers/specs/2026-09-24-el1-kernel.md; controller docs/superpowers/plans/2026-09-26-el1-completion.md.

## Constraints and review focus

- No anonymous allocation, COW or permission policy is duplicated in this increment. The first-touch host-exit slope remains red until actual EL1 service, transactional publication and elastic grants/return land.
- Preserve all guest registers, SP_EL0, faulting ELR and SPSR, ESR and FAR before calling Rust. Append FAR without assuming a larger aligned frame: current size is 280 and reserved stack space is 288; mechanically assert offsets and aligned capacity everywhere.
- A lower-EL data abort is EC 0x24. Same-EL faults and unrelated exceptions must retain their existing behavior. A fault must never be dispatched by its incidental x8 value as an SVC.
- No ELR increment on fault forwarding or retry. Forward through the existing fault decode, not syscall mailbox capture. Restore fault syndrome/address when the host transport relies on architectural registers.
- Keep IRQs masked through fault entry; no acquisition of a lock held by interrupted EL1. Do not enable guest page-table writes or remove host publication exclusion yet.
- Preserve image/ABI compatibility checks and on/off/GIC controls. Counters must identify genuine fault entry, not infer it from host exits; include initialization, snapshot and reset paths.
- Test denied user access, successful retry after a handler changes permissions, arbitrary x8, x16/x17 and general register preservation, frame bounds, and exclusion of kernel faults.

## Task 1: capture and classify data aborts

- [ ] Add red-first ABI and emitted-vector/classifier tests proving FAR capture, exact saved register offsets, lower-EL data-abort routing and distinct SVC/IRQ/other behavior.
- [ ] Extend TrapFrame and generated vector entry using existing machinery. Introduce a typed internal fault dispatch entry returning explicit host fallback until a later memory service is installed.
- [ ] Wire entry provenance accounting through the existing EL1 counters and their snapshot/reset paths without shifting or overlapping reserved ABI regions.
- [ ] Prove the emitted forward branch restores the saved fault context and preserves the existing non-EL1 path.

## Task 2: real guest witness and contract

- [ ] Extend the existing static embed-el1-sched fixture with a bounded fault-entry mode, and add a named signed embed test. Trigger a real EL0 stage-1 permission fault and validate si_addr/fault behavior plus retry and register preservation. Require a positive EL1 fault-entry counter; the disabled-EL1 control must preserve Linux behavior and report no EL1 fault entries.
- [ ] Register a precise fault-entry conformance contract/bindings and retain the full anonymous-first-touch contract unchanged. This increment is entry/forwarding acceptance only.
- [ ] Run VM-free tests and the bare-metal image build. Director captures signed red/green execution on the old/new source, same-image native behavior, default/EL1-off/GIC-off controls, exact artifacts and cleanup.

## Commands

`RUSTC_WRAPPER= cargo test -p carrick-el1-abi -p carrick-el1 -p carrick-mem --lib`

`RUSTC_WRAPPER= cargo build -p carrick-el1-image`

`RUSTC_WRAPPER= cargo test -p carrick-conformance-contract`

`cargo fmt --all -- --check`

Director-only signed command, with the exact test name established by the implementation:
`CARRICK_RUN_ID=<unique> RUSTC_WRAPPER= ./scripts/test-signed.sh carrick-embed el1_memory_fault_entry_preserves_context --exact --nocapture`

Full probe promotion and CI remain required before accepting integration; neither this plan nor a worker report proves completion.
