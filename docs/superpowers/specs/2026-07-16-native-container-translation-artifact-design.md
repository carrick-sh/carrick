# Native Container-Scoped Translation Artifact Design

**Date:** 2026-07-16

**Status:** approved design

**Campaign:** Darwin-native compiler performance

## Problem

The Darwin-native DSR backend creates a private translation cache for every
host process. Compiler workloads repeatedly execute the same Go and C toolchain
binaries in short-lived sibling processes, but each process decodes, plans,
emits, and publishes the same guest blocks again.

The exact one-file cgo reducer isolates this cost inside one already-started
container:

- Docker completes the inner command in 47.9 ms;
- Carrick's unprofiled inner p50 is approximately 2.55 s, or 53x Docker;
- a directionally representative profile records 2.814 s of aggregate guest
  thread CPU across 20 processes and 54 execution epochs;
- translation consumes 1.392 s, or 49.5% of that CPU;
- the processes perform 194,185 translations but observe only three existing
  process-cache hits;
- decode consumes 232 ms, emission 710 ms, and publication 223 ms.

This crosses the native compiler budget's decision rule: cold translation and
first publication are more than 30% of measured CPU. They are now the largest
identified on-CPU term.

The same investigation found an intermittent one-file cgo `SIGILL`: one of
five unprofiled fresh-container runs failed, followed by five stop-on-SIGILL
fresh runs and twenty same-container repetitions without a recurrence. That
event does not yet have a fault record and therefore has no attributed root
cause. The artifact design must make stale process state unrepresentable, but
must not claim to fix this unclassified signal.

## Goal

Reuse immutable DSR translation work across exec descendants of one native
container while preserving the current per-process `MAP_JIT` execution cache,
generation guards, invalidation, recovery metadata, and direct-link authority.

The first implementation slice must:

1. reduce translation plus publication CPU by at least 80% on the exact
   one-file cgo reducer;
2. improve the reducer's overall unprofiled p50 by at least 1.7x;
3. preserve identical output and status with no `SIGILL`, orphan, or stale-code
   failure in the bounded proof ladder;
4. expose the residual additive CPU budget so the next term can be selected
   immediately.

These are progress gates, not a performance bless. Native compiler performance
is not complete until representative inner-container workloads are
approximately 1.0x their Docker oracle.

## Non-goals

- No artifact persists across top-level container executions.
- No global cache directory, daemon, network service, or user-visible cache
  management is introduced.
- No shared executable mapping is used.
- No instruction, memory, exclusive, signal, or invalidation semantics are
  approximated for speed.
- No timeout or gateway ceiling is raised.
- The cache does not hide unsupported or ambiguously decoded instructions.
- The cache is not claimed to repair the intermittent cgo `SIGILL` without a
  fault record proving that diagnosis.

## Approaches considered

### 1. Container-scoped relocatable artifacts -- selected

One unlinked, bounded regular file belongs to the native container process
tree. Fork and the existing PID-preserving host self-reexec transport preserve
its fd. The file contains immutable data templates. Each consuming process
copies a validated template into its own private `MAP_JIT` cache and applies
typed process relocations before publication.

This attacks decode, planning, emission, and most publication construction
without sharing executable memory or process pointers.

### 2. Persistent cross-container AOT cache -- rejected

Persistence would increase warm coverage, but it would expand the trust and
invalidation boundary to filesystem ownership, runtime upgrades, host feature
changes, partial upgrades, and malicious or stale records. The measured
workload already has substantial reuse inside one container, so that expansion
is unnecessary for the first step.

### 3. Decoded-plan cache -- rejected as insufficient

Sharing only decoded instructions or `BlockPlan` values is simpler, but decode
is approximately 8% of the measured guest-thread CPU. Emission and publication
are larger. A plan-only cache is unlikely to produce the required overall
improvement.

## Authority and lifetime

The top-level native container creates a temporary regular file, unlinks it,
and retains the open fd as the artifact authority. The fd is inherited by host
fork descendants and explicitly carried across Carrick's host self-reexec in
the typed native exec capsule. The capsule records the fd flags, device, inode,
and size just as existing kernel-arena, waiter-table, xsignal, and prepared-image
authorities do.

The artifact authority ends when the last container descendant closes the fd.
A new top-level `carrick run` receives a new empty artifact. `carrick exec` may
share an artifact only when it joins the same live container execution and the
same authority fd.

The file is data storage only. Every process continues to allocate its own
anonymous private `MAP_JIT` `TranslationCache`. This avoids file-backed or
shared `MAP_JIT` policy, fixed-address mapping, cross-process icache, and direct
link coherence hazards.

## Artifact organization

The file has a fixed header followed by a bounded append-only record area and a
bounded lookup index. All integer fields have explicit widths and byte order.
Every offset and length is range-checked before use.

The header contains:

- magic and schema version;
- translator ABI fingerprint;
- host ISA and required feature mask;
- native page profile;
- artifact capacity and committed cursor;
- index geometry;
- a random container authority nonce.

Each record contains:

- a complete typed key;
- normalized emitted instruction words;
- PC map entries;
- recovery entries;
- unresolved direct-link sites and guest targets;
- typed relocation entries;
- exact source and dependency-page digests;
- payload length and checksum;
- a final atomic committed state.

Writers construct and checksum a record before making it visible. The committed
state is the last release store. Readers use an acquire load and never inspect
an uncommitted record. A writer killed at any earlier point leaves only
uncommitted space, which readers ignore.

The first version uses a process-shared file lock only to reserve append space
and publish the index entry. Decode, plan, emission, and checksum construction
happen outside the lock. Duplicate builders are allowed; the first valid index
publication wins and later equivalent candidates are discarded. This keeps the
correctness model simple before considering a lock-free allocator.

The file has a fixed capacity selected at container creation. Capacity
exhaustion is a normal cache miss, never a guest error. The first version does
not evict or compact records.

## Artifact key

An artifact key includes every input that can change normalized emitted code:

- translator artifact schema and ABI fingerprint;
- Carrick binary translation-policy fingerprint;
- host AArch64 ISA and required feature mask;
- native page profile and address-mode class;
- guest block start PC;
- exact source instruction bytes for the block;
- exact bytes and guest addresses of every source dependency read while
  decoding or planning;
- executable identity when available;
- all enabled fusion and lowering policy versions.

The executable identity improves lookup locality but is not sufficient
authority. Exact source and dependency bytes remain part of the key, so mutable
or generated executable pages may reuse an artifact only when their bytes are
identical.

Process generation numbers are not key authority. They identify a process's
current observation of guest memory and are rebound when the artifact is
consumed.

## Normalized template and relocations

An artifact contains no live process address. Values that differ across host
processes are represented by an exhaustive `ArtifactRelocationKind` enum. The
initial kinds cover:

- syscall, direct, indirect, sensitive, unsupported, and signal gateway
  addresses;
- generation-observation address and expected generation value;
- process host bias when an emitted sequence cannot load it from `DsrContext`;
- private cache entry addresses used by local control flow;
- per-process context or helper addresses that a later emitter adds.

Guest semantic constants such as a block PC, direct guest target, or literal
guest address remain in the template only when the key proves the same guest
coordinates. PC-relative branches within one template remain relative.

Every relocation records an instruction offset, kind, expected opcode mask,
and encoding shape. Replay first verifies the opcode mask, then patches the
typed value. Duplicate, overlapping, out-of-range, unknown, or unconsumed
relocations reject the record.

The emitter must account for every process-derived immediate at construction
time. There is no generic "patch u64" relocation and no heuristic scan of
emitted words. Tests normalize two fresh emissions made with deliberately
different process values; any unexplained word difference is an artifact
eligibility failure.

Direct-link sites are never imported as linked. Replay installs their original
resolver form and records the sites in the consuming `ProcessTranslator`.
Existing per-process publication and pending-link logic may then patch only the
private `MAP_JIT` mapping.

## Hit data flow

On a process-cache miss, `ThreadTranslator` obtains the current page-generation
observation and reads the candidate block bytes exactly as the live translator
does.

1. Build the complete artifact key from current source and policy authority.
2. Look up a committed record in the container artifact index.
3. Validate header identity, bounds, key, dependency bytes, checksum,
   relocation structure, PC map, recovery map, and direct-link metadata.
4. Reserve private `MAP_JIT` space.
5. Copy normalized words and apply every typed relocation with current process
   values.
6. Flush the private instruction cache.
7. Recheck the current generation observation.
8. Publish PC/recovery maps, sensitive metadata, dependencies, and unresolved
   direct-link sites through the existing per-process structures.
9. Publish the private entry in the existing concurrent publication index.

If the generation changes at any point, discard the private candidate and
retry through the current translation loop. A replayed block does not become
executable authority before the same final generation check used by fresh
emission.

## Miss data flow

On no record, ineligibility, validation failure, capacity exhaustion, or a
concurrent generation change, Carrick runs the existing decoder, planner,
emitter, and publication path.

After successful fresh emission, the emitter may normalize a candidate and
append it to the container artifact. Artifact construction is an optimization
side effect after the process-local block is already valid. Failure to append
does not fail or delay guest execution.

Instructions classified as `Unsupported`, memory accesses with unsupported
virtualization, ambiguous writeback, or any block whose emitted process
dependencies cannot be exhaustively typed are artifact-ineligible. They remain
on the current live path. Eligibility may expand only with a focused red-first
contract test and corpus evidence.

## Divergence and corruption handling

Malformed or incomplete records are invisible cache misses. Carrick records a
bounded diagnostic reason and translates locally.

If two fresh emissions for the same key normalize to different templates or
metadata, Carrick marks that key non-shareable for the rest of the container.
It retains process-local execution but emits one deterministic divergence
diagnostic. It does not guess which template is correct.

If the file header, authority identity, or index geometry changes after
adoption, Carrick disables the entire shared artifact for that process and uses
its private cache. Post-self-reexec adoption validates the fd before guest code
runs. A mismatched capsule fd is fatal at the capsule trust boundary, matching
existing typed fd authorities; corruption discovered during ordinary artifact
lookup is an optimization miss.

No artifact-validation failure is converted into a guest signal. In
particular, this work does not suppress, retry, or relabel a real `SIGILL`.

## Proactive instruction-state coverage

The existing AArch64 executable corpus audit remains the offline instruction
contract authority. The current corpus covers 28 executables and more than 16
million decoded instruction occurrences. It checks memory writeback and x18/x28
virtualization contracts.

Artifact eligibility adds stricter coverage:

- every copied instruction must have a deterministic `InstAction`;
- every memory instruction must have explicit address, writeback, and reserved
  register behavior;
- every process-derived emitted value must produce a typed relocation;
- unsupported and ambiguous actions cannot enter a shared artifact;
- normalization across different process-value fixtures must produce identical
  words and metadata after typed relocations are removed;
- replay and fresh emission must produce equivalent executable blocks,
  recovery behavior, and guest-visible outcomes.

The corpus audit reports every artifact-ineligible instruction family and its
occurrence count. This turns new compiler/toolchain instruction shapes into a
bounded backlog before a pathological live case depends on them.

## Observability

Low-tax counters distinguish:

- container artifact lookup and hit;
- miss by no-record, ineligible, validation, generation, capacity, or disabled
  key;
- bytes copied and relocations applied;
- fresh artifact candidates and committed records;
- duplicate and divergent candidates;
- private publication time after replay;
- live decode, plan, emit, and publication time retained on misses.

The profile reports artifact hit rate and replay CPU separately from ordinary
process-cache hits. It preserves the current additive accounting contract and
does not count a replay as a fresh translation.

## Testing strategy

### Artifact format and validator

Unit tests mutate every header field, length, offset, checksum, key field,
commit state, relocation kind, opcode mask, PC map entry, recovery entry, and
direct-link site. Each mutation must either validate exactly or become a typed
miss without reading outside the mapped file.

### Relocation equivalence

Emit the same block with varied private cache bases, gateway addresses, host
biases, generation addresses, and generation values. Normalization must yield
one identical artifact. Replay it into each fixture and compare the complete
fresh and replayed block metadata. Execute both through the existing DSR oracle
and compare guest register, memory, signal-recovery, and exit results.

### Lifecycle and concurrency

Fork/self-reexec tests prove the artifact fd identity and flags survive the
existing capsule. Concurrent tests cover duplicate builders, readers during an
uncommitted append, a writer killed before commit, capacity exhaustion, and a
generation change during replay. No reader may observe partial publication.

### Instruction corpus

Run the 28-executable AArch64 contract audit with artifact eligibility enabled.
The report must contain no unexplained x18/x28, memory-writeback, or relocation
gap. Known ineligible families remain explicitly counted rather than silently
accepted.

### Live correctness

Use the standard signed build. Run bounded stop-on-SIGILL repetitions of the
one-file cgo reducer, then the exact direct cgo command and focused Go compiler
row. Carrick and Docker run in separate phases. Every run has a unique
`CARRICK_RUN_ID` and scoped cleanup.

An intermittent `SIGILL` is a correctness failure and requires its native fatal
or stop-on-signal record before performance work continues. Profiling is
directional; output, status, and unprofiled timing are authoritative.

## Performance gates

Measure time inside the already-started container. Container startup is not
part of the Go fork/exec budget.

For the one-file cgo reducer:

- translation plus publication CPU decreases by at least 80%;
- overall unprofiled p50 improves by at least 1.7x;
- artifact replay is cheaper than 20% of the eliminated fresh-translation CPU;
- status and normalized output match Docker;
- no scoped descendant remains.

After this slice passes, re-profile the exact reducer and choose the next term
that accounts for at least 30% of residual CPU. Do not call the backend
performance-complete and do not stop the campaign at the intermediate gate.

The bounded exact c94 row may resume only after the reducer proves a material
win. Stop it at the existing bound if it remains an order of magnitude slower;
do not wait merely to obtain a timeout verdict.

The campaign-level terminal gate is approximately 1.0x Docker p50 on the exact
inner-container compiler workload, with correctness and bounded fan-out still
green.

## Feasibility spike hard gate

Do not begin the full production implementation from this spec. First build an
opt-in, bounded feasibility spike whose only purpose is to prove or falsify the
performance hypothesis on the exact inner-container cgo reducer.

The spike implements only the minimum end-to-end path needed for representative
reuse:

- one container-lifetime authority fd carried through the existing native exec
  capsule;
- fresh emission normalized into instruction words, PC/recovery metadata,
  unresolved direct links, and exhaustive typed process relocations;
- a bounded append-only shared store with coarse process-shared locking and a
  deliberately simple lookup structure;
- validated replay into each consumer's private `MAP_JIT` cache;
- counters for eligibility, committed artifacts, cross-process hits, replay
  CPU, fresh translation CPU, and validation misses;
- an opt-in environment switch that is absent from the user-facing CLI and is
  disabled by default.

The spike does not implement the production index, lock-free publication,
complete mutation matrix, default enablement, broad conformance promotion,
eviction, compaction, persistence, or long-term compatibility policy. Its
format may be replaced after the measurement gate. It must still be memory-safe,
generation-safe, typed, checksummed, bounded, and fail closed; "prototype" does
not authorize executing unvalidated code.

Run the spike against the exact same Docker identity and inner cgo command used
for the 47.9 ms oracle and approximately 2.55 s Carrick baseline. Measure at
least three unprofiled Carrick repetitions after one untimed warm-up, with
Carrick and Docker in separate phases. Profiling remains directional and must
not replace unprofiled wall authority.

Proceed to a separate full-scale implementation plan only if every spike gate
passes:

- a later host process consumes artifacts produced by an earlier sibling
  process in the same container;
- artifact hits cover enough work to reduce aggregate translation plus
  publication CPU by at least 80%;
- the exact one-file cgo unprofiled p50 improves by at least 1.7x;
- normalized output and exit status remain identical;
- no `SIGILL`, malformed replay, stale-generation execution, timeout, or scoped
  orphan occurs;
- replay CPU is less than 20% of the fresh translation plus publication CPU it
  replaces.

If any gate fails, stop before production hardening. Preserve the measurements,
classify whether eligibility, hit rate, replay cost, or the original CPU model
was wrong, and select the next measured performance term. Do not expand the
prototype merely because substantial code has already been written.

## Implementation boundaries

The first implementation plan covers only the feasibility spike and its hard
measurement gate. If and only if that gate passes, write a new production plan
that splits the remaining work into independently proven slices:

1. typed artifact schema, authority fd, validator, and mutation tests;
2. emitter normalization and exhaustive relocation recording;
3. private-cache replay and equivalence oracle;
4. append/index concurrency and capsule lifecycle;
5. correctness and performance promotion gates;
6. default enablement.

The default path must not consume shared artifacts until the replay oracle,
capsule lifecycle tests, corpus audit, and live bounded reducer all pass. A
temporary opt-in is allowed for measurement, but it is not a user-facing
configuration contract.
