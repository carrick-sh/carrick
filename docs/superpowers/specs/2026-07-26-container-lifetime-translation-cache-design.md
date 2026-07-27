# Container-lifetime AArch64 translation cache

**Status:** approved design.
**Lane:** Darwin/AArch64 native DSR only.
**Primary workload:** the conformance `go-build` case with a cold `GOCACHE`.
**Measured starting point:** 21,786 ms median, 10.7x the Docker oracle.

This design supersedes the persistent cross-run stages in
[`2026-07-26-file-backed-aot-cache-design.md`](2026-07-26-file-backed-aot-cache-design.md).
That document's signed Mach-O emitter, `dlopen` proof, and publish-cost
measurements remain inputs to this design.

## 1. Goal and boundaries

Share immutable AArch64 DSR translations among the guest processes created by
one top-level `carrick run`. A cold future invocation starts with an empty
cache. Durable caching under `CARRICK_HOME`, cross-container reuse, and cache
eviction are out of scope.

The first performance gate is five untraced, back-to-back `go-build` runs on an
idle host, reported as a median and compared with the 21,786 ms starting point.
The change must also preserve native correctness in Node and CPython workloads,
`just conformance-quick`, and `just ci`.

The cache is an optimization, never a new execution requirement. An unavailable,
contended, corrupt, stale, or unloadable entry falls back to the existing
`MAP_JIT` translator. A cache identity or source-validation mismatch is a miss,
not permission to execute questionable code.

This work does not change VMM/HVF, Linux/KVM, FreeBSD/bhyve, NetBSD/NVMM, or the
x86 native translator.

## 2. Why this is first

After biased exclusive fusion, one `go-build` consumes 53.1 thread-seconds:

| phase | CPU | share |
|---|---:|---:|
| translation | 28.3 s | 53% |
| translated execution | 19.9 s | 37% |
| cache-index preparation | 6.9 s | 13% |
| syscall dispatch | 4.1 s | 8% |

The workload starts 65 guest processes but executes the same small image set:
27 `compile`, 34 `asm`, two `link`, the driver, and the output binary. Those
processes translate their images independently.

The rejected per-block artifact experiment does not solve this problem. It
normalizes code, copies it into a new process's JIT, and rewrites process-local
values on every replay. It measured 2.95% slower at 71,244 hits and 21.7% slower
at 931,094 hits. The cache designed here maps already executable, immutable code
without a per-process write or per-block replay pass.

## 3. Selected architecture

### 3.1 Demand execution, batched publication

A process starts with the existing JIT and records blocks eligible for sharing.
It does not delay first execution to translate cold text.

Before process retirement, eligible blocks for one guest image are packed into
a bounded translation unit:

1. concatenate immutable emitted instructions;
2. rewrite intra-unit direct links against final unit offsets;
3. serialize immutable lookup and recovery metadata;
4. emit one Mach-O dylib whose `__TEXT` contains the unit;
5. ad-hoc sign it;
6. atomically publish the dylib and manifest;
7. allow later siblings to `dlopen` and index the unit.

One unit exports one base symbol. The manifest stores block entry offsets.
Thousands of exported block symbols would enlarge dyld metadata and make load
cost depend on block count for no semantic benefit.

The initial implementation may use the measured external `codesign -s -`
publisher. Publication counters must make signing cost visible. In-process
CodeDirectory emission is a later optimization if signing materially limits
the workload.

### 3.2 Container-owned cache authority

The top-level Darwin native run creates a private `0700` temporary directory
with an unguessable name. It opens the directory and records a typed authority:

- directory file descriptor;
- original descriptor flags;
- host device and inode;
- canonical path used by `dlopen`;
- translator ABI version.

Forked guest processes inherit the authority. The native self-reexec capsule
carries it across the host `execve`, using the same validated descriptor
transport pattern as the kernel arena, futex waiter table, and artifact spike.
Resume rejects a changed descriptor identity.

Only the owner removes the directory after the container lifecycle ends.
Forked children and self-reexec images may publish or load entries but never
own cleanup. A child crash therefore cannot delete a sibling's cache.

No cache authority is reconstructed solely from `CARRICK_RUN_ID` or another
environment string. Run ids are diagnostic labels, not capabilities.

### 3.3 Image identity

Guest VA is not code identity. The lookup key is:

```text
TranslationUnitKey {
    executable: ExecutableIdentity,
    segment_file_offset,
    segment_file_len,
    guest_va_start,
    guest_va_len,
    source_fingerprint,
    native_page_profile,
    address_mode_and_host_bias,
    translator_abi,
}
```

`ExecutableIdentity` uses stable host metadata when the loaded image has a
host-file authority: device, inode, size, modification seconds, and
modification nanoseconds. For synthesized or in-memory images it uses the
already available executable digest. The cache does not add a second whole-file
hash.

`source_fingerprint` covers the exact guest source bytes represented by the
unit. A loader validates it before making the unit visible to translation
lookup. This is defense in depth against stale metadata and also protects
images whose backing file is modified without a useful timestamp change.

The translator ABI is an explicit ordinal covering emitted-code layout,
`DsrContext`, manifest schema, recovery semantics, and address-mode lowering.
Changing any of those makes old units misses.

### 3.4 Portable emitted code

Gateway addresses already load through `DsrContext`. Published code must contain
no host code address and must never be rewritten in the loading process.

The remaining process-local generation state moves behind a context seam.
`DsrContext` holds a pointer to a process-local array of:

```rust
struct GenerationBinding {
    current: *const AtomicU64,
    expected: CodeGeneration,
}
```

Each published block encodes a stable `u32` binding index. Its entry prelude
loads the array pointer through `x28`, locates the 16-byte binding, loads the
current-generation pointer and expected value, then performs the existing
acquire load and comparison. Directly chained targets execute their own prelude,
so generation correctness does not depend on returning to Rust between blocks.
The existing recovery map covers the temporary `x16`/`x17` use.

The implementation plan includes a disassembly-backed instruction-cost test,
but it may change only the encoding of this lookup, not its data or lifetime
contract. Loaded code stays byte-for-byte immutable and rejects a changed source
generation before executing stale code.

The complete biased-mode host-bias value is part of
`address_mode_and_host_bias`. A unit emitted for one bias is a miss in a process
with another bias. This avoids adding a bias load to every guest memory access
and makes the existing encoded bias safe without assuming it is globally
constant.

### 3.5 Eligibility and invalidation

The first version publishes only blocks sourced from executable image pages
that remain at their initial generation through publication. It excludes:

- anonymous executable memory;
- writable-and-executable or previously written pages;
- source pages whose generation changed;
- blocks with unresolved process-local materializations;
- blocks whose metadata cannot be serialized losslessly;
- units exceeding the bounded publish size.

A load validates identity, source fingerprint, schema, translator ABI, address
mode, page profile, all entry offsets, and all metadata ranges before `dlopen`
results become indexable.

If a page generation changes after a unit was indexed, the normal generation
guard exits stale. The process removes those entries from its lookup and
continues through JIT translation. Published files remain immutable.

### 3.6 Concurrency and atomicity

Publication is first-writer-wins per full unit key:

1. write uniquely named temporary dylib and manifest files inside the authority
   directory;
2. sign and validate the temporary dylib;
3. take the per-key publication lock;
4. recheck for an already published valid unit;
5. atomically rename the manifest and dylib into their final names;
6. fsync only if measurement shows it is required for visibility within the
   running container; crash durability is not a goal.

Readers never open a temporary name. A reader that observes only one half of a
pair treats the entry as a miss. The manifest contains the dylib digest and the
dylib contains or exports the unit identity, preventing cross-pair assembly.

Duplicate publishers discard their temporary output and use the winner.

## 4. Runtime lookup and metadata

Each `ProcessTranslator` keeps:

- the existing JIT translation cache;
- a read-only registry of loaded shared units;
- a guest-address index keyed by image identity and generation;
- `dlopen` handles for the lifetime of the process;
- counters for lookup, validation, load, publication, and fallback.

Lookup order is:

1. current process JIT entry;
2. loaded shared-unit entry for the current image identity and generation;
3. validate and load a published unit, then retry the shared index;
4. translate into JIT and record an eligible publication candidate.

Shared-unit recovery metadata is addressed relative to the unit base. Existing
fault and kick recovery must accept a code range from either JIT or a loaded
unit and resolve the corresponding immutable metadata without copying it into
the JIT cache.

Direct links within one unit are finalized before signing. Links between units
and links from JIT code remain on the existing resolver path in this slice.
Indirect branch chaining is the next ranked phase after the cache is measured.

## 5. Observability

The cache adds low-frequency counters to the existing native performance
protocol:

- unit lookup attempts, hits, and misses;
- units loaded and load CPU/wall time;
- blocks and code bytes mapped from units;
- publication attempts, winners, duplicates, and failures;
- emit, sign, and validation CPU/wall time;
- source-identity, source-fingerprint, ABI, schema, and `dlopen` rejections;
- JIT translations avoided;
- fallbacks by typed reason.

No per-block USDT probe is enabled during wall-clock measurement. Exact block
counts may be collected in a separate traced run, following the handoff's
measurement rule.

## 6. Red-first proof

The first integration test creates two different AArch64 ELFs with identical
load placement and different return values. It runs them as concurrent sibling
guest processes under one cache authority.

The red control uses a deliberately VA-only key and must demonstrate cross-image
aliasing or explicit identity collision. The production key must make both
programs return their own value, with separate published identities. Reverting
the identity fields must make the test red again.

Additional red-first tests prove:

1. process-local generation addresses do not appear in published instructions;
2. a changed source fingerprint is a miss;
3. a changed generation exits stale instead of running the cached block;
4. a partial or corrupt publish pair falls back to JIT;
5. two publishers converge on one valid immutable winner;
6. self-reexec preserves and validates cache authority;
7. a loader never writes to the signed code mapping.

## 7. Verification and performance decision

The implementation is not complete at compile time. Required evidence is:

1. focused unit and integration tests with their red controls recorded;
2. `vmmap` proof that loaded translation text is file-backed `r-x`;
3. a native runtime demo showing a later sibling loads blocks and avoids
   translations;
4. five idle, untraced `go-build` samples, median reported against 21,786 ms;
5. a profiled run showing translation CPU and translation count decreased;
6. Node and CPython smoke workloads;
7. `just conformance-quick`;
8. `just ci`.

Before each performance run, check for orphaned spin loops, machine load, active
compilers, and concurrent Docker work. Carrick and the Docker oracle run in
separate phases.

The cache stays only if the measured `go-build` median improves and the
translation counters explain that improvement. A neutral or negative wall-time
result is not rescued by projected savings. If publish/load overhead consumes
the saved translation time, resize units or change publication timing and
remeasure.

## 8. Rejected alternatives

### Persistent cross-run store

Rejected for this goal. It adds eviction, trust, tamper, upgrade, and stale-file
policy before proving that shared translations help one real container
lifecycle.

### Per-block normalize and replay

Rejected by measurement. It writes and rebinds every block in each process and
was slower at both measured hit volumes.

### Eager whole-image translation

Deferred. It maximizes theoretical reuse but translates cold code, delays first
instruction, and greatly enlarges the first correctness surface. Demand
recording measures which blocks deserve publication.

### Mach named memory entries

Rejected. A signed dylib is the AMFI-supported executable-file path, is naturally
file-backed, survives host self-reexec, and uses the unified buffer cache.

### Indirect chaining before translation sharing

Deferred, not rejected. Indirect exits are 82.9% of residual gateways, but
translation is the larger measured CPU phase and is repeated across 65
processes. Chaining is the next phase after this cache has a measured result.
