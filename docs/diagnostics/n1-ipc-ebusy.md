# N1 Cumulative IPC EBUSY Diagnostics

## State
- Inherited branch at `853534225` (advisory stack mappings in EL1 root).
- Milestone 1: Live-residency authentication for published frame grants implemented and verified red/green via `serial_host_prepared_grant_subsequent_page_authenticates_live_residency_without_fresh_grant`.
- Added test-teardown assertion `assert_no_surviving_portal_claims` across all tests in `el1_sched.rs`.

## Evidence
- Diagnostic commits `14c162e9c` and `cf9e08b3f` showed child read() getting EFAULT due to PREPARE refusal.
- `crates/carrick-aarch64/src/user_transfer/prepared.rs` records `owner PREPARE refused: completion` where `completion.errno == 16` triggers `MemoryPrepareError::Fault` (lowered to EFAULT).
- Running `./scripts/test-signed.sh carrick-embed el1_ipc_ --nocapture` reproduces `receive fd=41 buf=0x600143a8f8 errno=Bad address (os error 14)` at pipe n=64 during `el1_ipc_two_processes_blocking`.
- `just lint-domains` passed (exit 0) on the clean tree; the predecessor failure was caused by dirty working tree inputs during compiler capture.

## Next Step
- Determine whether PREPARE refusal comes from host-side code (`carrick-vmm-hvf` / `carrick-kernel` host paths) or shared EL1 code (`carrick-el1` mm_portal, mmu-core, sched-core).
- Trace holder identity and sequence during `el1_ipc_two_processes_blocking`.

