# The global-frame lease identity has no generation, and Darwin recycles it 100% of the time

**Date:** 2026-08-19
**Status:** root cause CANDIDATE for `cpython-importlib` (147 rows) — precondition
measured and confirmed; the crash link itself is NOT yet proven.

## The predicate

`global_frame_host_owner_matches` (`crates/carrick-vmm-hvf/src/trap.rs:918`)
authenticates a non-owning per-thread mapping row against the live owner:

```rust
let owner_host_addr = global_frame_host_owners().lock().get(&(ipa, length))
    .map(|owner| owner._mapping.as_ptr() as usize).unwrap_or(0);
let matches = owner_host_addr != 0 && owner_host_addr == host_addr;
```

Its own doc comment states the hazard it exists to close:

> After the last logical reference retires, macOS may immediately recycle that
> host VA for an unrelated frame. A `mach_vm_region` liveness query would then
> accept the stale pointer and let anonymous-reuse zeroing scrub the unrelated
> allocation. The `(IPA, length, host pointer)` triple is the owning lease
> identity and therefore the only safe HVPatch predicate.

**The triple carries no generation** — `GlobalFrameStage2Lease`
(`trap.rs:4063`) is `{base, length, mapped, active, release_ipa}` and
`GlobalFrameHostOwner` (`:818`) has none either — and **all three components are
recycled together**:

- the IPA returns to `GlobalFrameIpaAllocator`'s coalescing free list on lease
  drop and is re-issued smallest-fitting, lowest-base-first (`trap.rs:3954`,
  `:4014`);
- the host VA comes from a plain `mmap(NULL, …)` with no pool
  (`carrick-host/src/host_mapping.rs:37`);
- the length is the same 16 KiB compound every time.

So the predicate the comment calls "the only safe" one is defeated by exactly
the recycling it names — one level up.

## The precondition, measured

Does Darwin actually recycle the host VA? Host-only, no carrick, no build:

```
len= 16384: immediate same-VA reuse 499/499, distinct VAs=1, max reuse of one VA=500
len= 65536: immediate same-VA reuse 499/499, distinct VAs=1, max reuse of one VA=500
```

`reducers/host-va-recycle.py`. **Not "may recycle" — it recycled on every single
one of 500 cycles, returning exactly ONE address.** The doc comment's "may" is
far too weak: for a `map_shared_anon` / `munmap` cycle of a fixed size, reuse is
deterministic.

## Why this matters

`self.mappings` is a **plain per-thread `Vec`** (`trap.rs:3482`) while
`page_tables`, `frame_inventory` and `protections` are `Arc`-shared, and a clone
child receives a COPY of its creator's rows (`:4141`, `:4190`). `munmap` prunes
the global alias registry and only the CURRENT thread's rows (`:10178`,
`:9978`) — the code says so at `:10639`. A sibling's row therefore outlives the
lease it names, and once the triple recurs it silently re-authenticates.

The consequence is the shape `1e970696e` was written against: the
anonymous-reuse scrub resolves through the stale row and
`core::ptr::write_bytes(target, 0, chunk_len)` (`trap.rs:9705`) zeroes a live
16 KiB granule. It re-enters through a path that fix structurally cannot see,
because `retained_output_lacks_exclusive_claim` (`:6829`) tests for CROSS-mm
sharing (frame refcount > 1) and this is WITHIN one mm at refcount 1.

CPython 3.12 allocates every interpreter data-stack chunk as a 16 KiB anonymous
`mmap` and `munmap`s it on frame pop, so one chunk is exactly one lease — which
is why a thread-churning test is the workload that finds it, and why a zeroed
chunk yields `ldr x0,[x24]; ldr x1,[x0]` with `fault_address: 0`, the recorded
`cpython-importlib` signature.

## What is NOT established

That this is *the* `cpython-importlib` crash. The precondition is confirmed and
the path is traceable line by line, but the link to that specific SIGSEGV is
inference. Two experiments settle it, neither needing a fix first:

1. Arm `scripts/dtrace/hvpatch-global-frame-stage2-inventory.d` (`dtrace -Z`,
   `carrick*:::` — the carrier is a child, and per that script's header zero
   rows means the capture FAILED, never "no edges happened") and count exact
   `(ipa, len, host)` recurrences after retirement during the reducer.
2. Diagnostic-only: `std::mem::forget` the owner in
   `retire_global_frame_host_owner` (`trap.rs:902`), which leaks the host buffer
   AND stops the IPA being re-issued, so both halves stop recurring in one edit.
   If the crash rate goes ~5/8 -> 0/8 while the unmodified binary stays ~5/8 in
   the same session, it is confirmed. Sample BOTH arms — the verdict is
   load-probabilistic, so a one-run-per-point comparison converges on the wrong
   answer.

## The fix, when it is confirmed

A monotonic generation on `GlobalFrameStage2Lease`/`GlobalFrameHostOwner`,
stamped into the mapping row at publication and compared in
`global_frame_host_owner_matches`. That is the "exact current owner generation"
AGENTS.md already prescribes for HVPatch and which does not exist as a value
today. Note a `MappingGeneration` type already exists in the frame inventory
(`trap.rs:5083`) and is simply not used on this path.

Worth closing regardless of whether it is this crash: per-thread state holds raw
pointers to `munmap`ped host memory, authenticated by pointer value alone,
against an allocator that provably hands the same pointer straight back.
