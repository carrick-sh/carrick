# AArch64 soft CPU code residency across provider exits

The soft AArch64 vCPU (`SoftAarch64Vcpu::run`) calls the dispatcher once per
block quantum and once per provider exit. Before #2717 each call started
with an empty block cache, so every `HVC #2` handoff decoded, emitted and
published its hot set again. The work grew with exits times hot set.

The vCPU now owns a `DispatchCache` and passes it to every
`run_controlled` call. The cache holds compiled code only. Each call
still starts with no stage-1 translations and no native links. A block is
reused only after the dispatcher translates its PC through the current
tables and matches the physical frame and its code generation. Code
survives a call only when memory names its extent inventory
(`GuestMemory::code_cache_domain`). A different inventory, block limit,
chaining mode or inline-memory mode starts with an empty cache. Plain
`run` calls keep code for their own duration only.

## Why reuse is safe

Code generations come from `SoftStage2`'s `ExtentTable`. Generations for a
frame only increase within one inventory, and a cleared frame resumes
from its last value. Inventory identities are never reused. The
generation advances on:

- guest stores to a code frame;
- host writes through `write_gpa_bytes` (the engine's `translated_write`,
  `zero_backing` and loader writes);
- `publish_user_executable` for each new EL0-executable leaf, the soft
  lane's `set_pte_at` instruction-cache point;
- `IC IVAU` on the frame. `IC IALLU` and `IC IALLUIS` clear the whole cache.

Removing execute permission advances the generation, and retiring a window
clears the frame. Host
code that writes guest code through a raw `host_ptr` must publish it with
`publish_user_executable`, as it must for HVF's instruction cache.

Set `CARRICK_SOFT_AARCH64_HANDOFF_CACHE=0` to discard residency at every
call.

## Witnesses

All four run on the production carrier with production kernel dispatch,
on x86_64 and on ARM64 hosts.

- `soft_carrier_emits_the_hot_set_once_across_provider_exits` loops
  `svc; b .-4` for 10 and 100 `getpid` handoffs. It emits 9 blocks at both
  scales. Main emitted 47 and 407, as does the opt-out.
- `soft_carrier_serves_rewritten_code_and_faults_after_prot_none`
  rewrites the resident `svc` word with a guest store after an RWX
  `mprotect`, then with a host `read` across a provider exit. It must
  serve `svc #0`, `svc #1` and `svc #2` in order. After
  `mprotect(PROT_NONE)` the next fetch faults with SIGSEGV at the
  resident `str`'s PC.
- `soft_carrier_serves_rewritten_code_and_the_remapped_page` ends with a
  `MAP_FIXED` private file mapping over the page. The guest must run the
  file's `svc #3` where the resident block held the `str`.

- `soft_carrier_faults_after_munmap_of_resident_code` maps a file page
  holding `svc #2; b .-4` at a kernel-chosen address, branches into it,
  runs the loop twice so both blocks are resident across provider exits,
  then unmaps it. The fetch of the resident `b .-4` must fault with
  SIGSEGV at its address. (`munmap` of ELF text is refused on the soft
  carrier today, #2725, so the witness unmaps a file mapping.)

Each rewrite witness is red under a mutation that removes one
invalidation; the munmap witness is red when a resident block is served
without re-translating its PC:

| mutation | prot-none | remap | munmap |
|---|---|---|---|
| generation compare removed (frame only) | red | red | green |
| guest-store invalidation removed | red | red | green |
| `write_gpa_bytes` invalidation removed | red | red | green |
| resident block served when its PC does not translate | red | green | red |
