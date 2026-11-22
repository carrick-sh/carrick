# Soft CPU code residency within a typed budget

Contract: `softcpu.code-residency`
(`conformance-contracts/contracts/softcpu-code-residency.toml`).

Both soft CPUs keep decoded and emitted blocks in one
`carrick-softmmu::block_cache::BlockCache`. The AArch64 soft vCPU owns it
through `DispatchCache`; the x86 `SoftCpu` owns it directly. Until #2717 the
cache was a 1,024-entry FIFO. CPython startup on the AArch64 soft carrier
touches about 78,000 distinct blocks, and 98.71% of its 6.05 million decodes
re-decoded a block FIFO capacity had evicted. The eval loop was pushed out
by every 1,024 cold blocks that passed through.

## Policy

- **Use-aware eviction (CLOCK).** A cache hit sets the entry's reference
  bit. When the cache must make room, the hand evicts the first entry
  without one and clears the bits it passes. Code hit since the hand last
  passed survives, so a hot loop outlives a scan of cold one-shot blocks.
  A replaced key keeps its slot. New entries start unreferenced.
- **Typed owner budgets.** Each owner passes a `ResidencyBudget`: a
  `ResidentBlocks` count and a `CodeBytes` byte budget. Both hold after every
  insert. A single block larger than the byte budget is kept alone. The
  owners' budgets are `AARCH64_RESIDENCY` (`carrick-softcpu-aarch64`
  `dispatch.rs`) and `X86_RESIDENCY` (`carrick-softcpu-x86` `cpu.rs`):
  16,384 blocks and 64 MiB each.
- **Bytes are host mappings.** Prepared code reports its footprint through
  `CodeFootprint`. Each block is published into its own
  `JitCodeBuffer`, so its footprint is `JitCodeBuffer::mapped_bytes`, the
  page-rounded mapping (4 KiB for every block up to 4 KiB of host code).
  At 16,384 blocks the cache holds at most 64 MiB of executable mappings,
  and the separate mappings stay far below Linux's default
  `vm.max_map_count` of 65,530.
- **Reclamation follows eviction.** Evicting an entry drops its value at
  once. When nothing else holds the block, its `JitCodeBuffer` is unmapped
  then. On the AArch64 carrier a native link may hold an evicted block until
  the links are revoked, which happens at least at every dispatcher return,
  so at most `2 * CHAIN_SLOTS` evicted blocks outlive their entry.
- **Opt-out.** `CARRICK_SOFT_CODE_RESIDENCY=0` (exactly `0`) selects
  `ResidencyBudget::OPT_OUT` for both soft CPUs: 1,024 blocks, no byte
  budget, insertion order. It is the same implementation with no reference
  bits, which is FIFO. It exists for the paired A/B and is deleted once the
  use-aware budget has measured better.

Residency changes only cost. A resident block is still reused only after
the dispatcher re-translates its PC and matches its frame and code
generation (`arm.softcpu.handoff-residency`, `x86.softcpu.cache-smc`).

## Witnesses

AArch64, on the production carrier (`run_single_process_with_executor_and_setup`)
with real decode, dispatch and residency, on x86_64 and ARM64 hosts:

- `soft_carrier_keeps_a_4096_block_working_set_resident_across_passes`
  runs `svc; b .+4 x 4,096; b` back for 3, 10 and 30 passes. It must emit
  at most 8 blocks more than it first sees (4,105). The FIFO emitted
  12,307, 41,007 and 123,007.
- `soft_carrier_keeps_a_hot_loop_resident_through_a_cold_scan` interleaves
  a 16-block hot loop with 1,024 chunks of 64 cold one-shot blocks (65,536
  blocks, four times the block budget). Every hot block must be emitted
  once. The FIFO emitted each 65 times.
- `soft_carrier_releases_evicted_code_within_its_budget` declares a
  footprint of 1/64 of the byte budget per block and runs the 4,096-block
  working set. Live code (cached or in flight) must never exceed 65 blocks,
  the cache's byte high-water mark must stay within the budget, and no code
  may outlive the carrier. The FIFO kept 1,025 blocks live.

x86, on `SoftCpu::step_block`:

- `working_set_of_4096_blocks_stays_resident_across_passes`: each of the
  4,097 blocks translates and emits once at 3, 10 and 30 passes. The FIFO
  translated 12,291, 40,970 and 122,910.
- `hot_loop_survives_a_cold_scan`: a 16-block hot loop is never
  re-translated across 65,536 cold blocks. The FIFO re-translated it after
  16 cold chunks.
- `capacity_eviction_keeps_other_resident_blocks`: one block past the
  budget evicts exactly one block, and the second key stays resident.

`carrick-softmmu` unit tests cover scan resistance, FIFO order under the
opt-out, the byte budget with immediate drop of evicted values, and a
sweep over an all-referenced cache.

The CPython production-dispatch witness
(`soft_cpu_runs_dynamic_cpython_through_production_dispatch`, hosted ARM64)
prints the decoded and executed block counts and the cache census.
