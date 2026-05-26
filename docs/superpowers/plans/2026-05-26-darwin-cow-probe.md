# Darwin COW Probe (Plan 5) — Findings

> Spec: `docs/superpowers/specs/2026-05-26-durable-memory-architecture-design.md` §5 + decomposition item 5 + open probe #2: *"Can `mach_vm_remap(copy=true)` … produce a correct sparse private fork snapshot while preserving HVF coherence?"* — and is it cheaper than the explicit `mincore` copy?

**Probe:** `crates/carrick-runtime/tests/mach_cow_probe.rs`
(`cargo test -p carrick-runtime --test mach_cow_probe -- --nocapture`)

It builds a guest-region-shaped buffer (`mmap(MAP_ANON|MAP_SHARED|MAP_NORESERVE)`, exactly how carrick backs private guest RAM), dirties a sparse subset (a forked heap/stack shape), then compares the current explicit `mincore`-gated copy against `mach_vm_remap(copy=TRUE)`, and — the gating check — mutates the SOURCE after cloning to see if the write leaks into the clone.

## Findings (64 MiB region, every 8th page dirty)

| Method | Time | Write-isolated? |
|---|---|---|
| Explicit `mincore` copy (current `clone_region_for_child`) | ~4.78 ms | n/a (true copy) |
| `mach_vm_remap(copy=TRUE)` | ~0.61 ms | **YES — source mutation did NOT leak into the clone** |

- **~7.8× faster**, and
- **correctly write-isolated even on a `MAP_SHARED` source** — which *contradicts the spec's suspicion* ("Darwin COW is not a drop-in replacement … a normal host `fork(2)` does not COW-isolate those shared mappings"). `mach_vm_remap(copy=TRUE)` is NOT a `fork(2)` inherit; it creates a fresh COW copy object, so it isolates where `fork` would share.

## Verdict

`mach_vm_remap(copy=TRUE)` is a **strong candidate** to replace the explicit sparse snapshot for true-fork private regions: dramatically cheaper and correctly isolating. It is **not yet adopted** — one gate remains, exactly as the spec requires ("until a probe proves both correctness and lower cost under HVF"):

- **HVF-coherence integration test (next step before adoption):** prove that a `mach_vm_remap`-cloned buffer, when `hv_vm_map`'d as the child's guest RAM, stays coherent with the guest CPU (the same class of coherence that forced `MAP_SHARED` backing originally). This needs a real forked-guest HVF run, not a unit test. Until it passes, the explicit `mincore` snapshot remains the production path (the spec's mandated fallback).

The write-isolation correctness and the cost win are now **proven**; adoption is gated solely on that HVF-coherence check. The probe is committed as a permanent regression/benchmark so the finding can be re-confirmed across macOS versions.
