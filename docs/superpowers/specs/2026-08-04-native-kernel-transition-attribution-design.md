# Authenticated native kernel-transition attribution design

Date: 2026-08-04

Status: direction approved; this written design is the review checkpoint before
implementation planning. No implementation is authorized by this document
alone.

## 1. Decision

Carrick will add one first-class, typed `native-kernel-transition` trace profile
that measures two independent populations over the same authenticated native
process tree:

1. periodic CPU samples in which every `kernel-non-syscall` sample retains both
   the live kernel PC and the documented pre-transition user PC from
   `uregs[R_PC]`; and
2. exact `vminfo:::as_fault` event counts keyed by that same pre-transition
   user-PC domain, with `zfod`, COW, and other fault outcomes retained as
   separate count-only corroboration.

The CPU population is the opportunity authority. Exact fault counts can prove
amplification and strengthen a causal interpretation, but they are not CPU
samples, do not share a denominator with CPU, and cannot by themselves select
an optimization.

Every transition PC is resolved after capture against the authenticated host
image catalog or the exact own/inherited JIT snapshot that covered the process
image when the event occurred. JIT words are decoded by the existing Rust
NativeShape classifier. Every kernel PC is retained as an address and resolved
against the live kernel-symbol overlay plus a matching KDK image/dSYM; exact
instruction bytes and all same-address aliases are preserved so a convenient
symbolizer name cannot become the diagnosis.

Two accepted cold-build captures from one frozen signed binary decide the
result. A source-distinct, non-overlapping mechanism may advance only when it
accounts for at least 10% of **all sampled CPU in each capture**, moves by no
more than five percentage points between captures, and survives source audit as
Carrick-removable work. If nothing meets that gate, this attribution line stops
without a runtime patch.

## 2. Why this profile is required

The current cold Go-build authority remains 8,254 Carrick total CPU-seconds
against 811 Docker CPU-seconds, or 10.1776x. Nothing in this design changes that
score. The next stable unattributed population is the native-wall
`kernel-non-syscall` category:

- capture A: 20.2712% of all sampled CPU;
- capture B: 19.9012% of all sampled CPU.

That is large enough to contain a source-distinct opportunity above the
campaign's 10% threshold, but the current artifacts cannot name one.

The exploratory kernel-PC histogram initially made
`ml_set_interrupts_enabled_with_debug+0x4c` appear to own roughly 18% of all
CPU. Exact KDK disassembly disproved that reading: the sampled instruction is
the landing PC immediately after `msr DAIFClr, #0x7`. It is where deferred
interrupt/fault work resumes, not evidence that the named function itself
consumes that CPU. This is exactly the symbolizer-alias and transition-boundary
failure mode that Carrick's tracing rules require us to eliminate.

Three additional facts constrain the design:

- Darwin DTrace documents `uregs[]` as the register state immediately before
  the current thread's most recent user-to-kernel transition. Live compiler
  checks on this host accept `uregs[R_PC]` but reject `regs[29]` and
  `kregs[29]`; an ordinary DTrace profile therefore cannot recover a reliable
  live kernel frame pointer or saved kernel caller.
- The active `vminfo:::as_fault` provider already exposes the faulting user PC
  through `uregs[R_PC]`. Historical raw fault-PC counts were not authoritative
  because dozens of short-lived ASLR process images reused raw address space
  without birth/image/snapshot binding.
- NativeShape already proves that Carrick can capture lifecycle-complete JIT
  snapshots and resolve sampled PCs through fork ancestry with 100% coverage.
  Reimplementing that join would create two answers to the same question.

The missing observation is therefore not another broad stack profile. It is a
typed joint census of live kernel location and the user instruction that caused
or preceded entry into that kernel interval, with exact fault-event counts over
the same identity domain.

## 3. Goals and non-goals

### Goals

- Partition all periodic samples exactly into user, kernel, and invalid
  populations, then partition kernel samples into named syscall, Mach trap, and
  non-syscall state with the existing balanced-entry authority.
- For every non-syscall kernel sample, retain the exact pair
  `(kernel_pc, pre_transition_user_pc)` under a birth/image/runtime identity.
- Count every tracked `as_fault` event exactly by the same user-PC identity and
  retain independent exact totals for the other qualified fault outcomes.
- Resolve every carried user PC to exactly one own/inherited JIT snapshot or
  host image, and every non-syscall kernel PC to exact matching kernel bytes.
- Reuse one Rust snapshot loader, ancestry resolver, instruction classifier,
  launch authority, kernel-symbol overlay, and lifecycle validator.
- Produce deterministic typed capture, census, and paired-comparison artifacts
  that can independently regenerate every percentage and carry/stop verdict.
- Name the next source-distinct, non-regrettable >=10%-of-all-CPU opportunity,
  or close this bucket without speculative implementation.

### Non-goals

- This design does not optimize the runtime, change the shipped execution path,
  or authorize a performance claim.
- It does not treat traced elapsed time as product timing. The profile is
  intentionally high perturbation because `as_fault` is a very hot provider.
- It does not infer CPU cost from fault count, project one fault's cost across
  all faults, or add CPU and fault percentages.
- It does not weaken Linux memory, fault, register, signal, fork, or exec
  semantics to make a candidate removable.
- It does not make FBT presence evidence of an active kernel path, recover a
  kernel caller from undocumented stack layout, or trust one printed symbol
  name as kernel-source authority.
- It does not revise the closed NativeShape evidence schemas or the existing
  native-wall/native-fault artifacts. Shared Rust machinery may be factored out
  without changing their accepted semantics.
- It does not implement eager whole-image translation. That remains a deferred
  future improvement and would not replace dynamic/JIT-on-JIT attribution.

## 4. Alternatives considered

### 4.1 Recover the live kernel caller

Rejected. A local experiment found the apparent saved frame pointer in a known
prologue, but DTrace exposes neither `regs[]` nor `kregs[]` on this host. Reading
arbitrary kernel stack offsets would bind the profile to an unproved compiler
frame layout and would still miss interrupt/trap paths without that prologue.
LLDB/core inspection remains appropriate for a disputed individual process,
not for weighting the complete cold-build CPU population.

### 4.2 Attribute by kernel provider or kernel stack alone

Retained only as corroboration/fallback. Provider counts and sampled stacks can
describe kernel composition, but the active fault path contains local or
blacklisted functions that FBT cannot bracket, and a stack does not identify
the Carrick/guest instruction that repeatedly induces the work. It cannot
safely choose a source patch by itself.

### 4.3 Fault-PC counts only

Rejected as selection authority. Exact `as_fault` counts can reveal one hot
transition PC, but event frequency is not CPU residency. A frequent cheap fault
and an infrequent expensive fault can reverse order when weighted by CPU. The
new design keeps the exact counts because they are strong mechanism evidence,
then independently requires the same transition owner to be large in periodic
CPU samples.

### 4.4 Selected dual CPU/fault transition-PC census

Selected. `uregs[R_PC]` is available in both the periodic kernel sample and the
active fault event, and the existing lifecycle/snapshot authorities can make
that PC meaningful after the processes exit. It directly answers which
user-side source instruction owns stable non-syscall kernel residency while
preserving an independent exact amplification counter.

## 5. New first-class profile

`TraceProfileKind` gains `NativeKernelTransition`, exposed as:

```text
carrick trace --profile native-kernel-transition \
  --kernel-debug-image <kernel.release.t8132> \
  --kernel-debug-symbols <kernel.release.t8132.dSYM> \
  --native-kernel-transition-snapshots <snapshot-dir> \
  --trace-out <capture.raw.trace> \
  --summary-jsonl <capture.receipt.jsonl> -- \
  run --exec-backend native <digest-pinned-image> <exact-command...>
```

The exact option spellings may be normalized in the implementation plan if an
existing general kernel-debug-image vocabulary is established first. Their
contract is fixed: the trace command must possess and authenticate the exact
KDK executable and dSYM used for address normalization before it launches the
target. Ambient KDK discovery is not accepted evidence authority.

The bundled D program is
`scripts/dtrace/native-kernel-transition.d`. Its program bytes are hashed into
the authority header. The profile uses the in-process libdtrace runner, launch
qualification, credential drop, native-process-tree tracking, post-stop live
kernel-symbol callback, natural-completion contract, and seven-field
interruption/drop receipt already used by the accepted typed profiles. It uses
`dtrace -Z` semantics for Carrick USDT probes that appear after launch.

The raw wire grammar is `NKTRANS1`. The public JSON schemas are:

- `carrick.native-kernel-transition-authority.v1`;
- `carrick.native-kernel-transition-capture.v1`;
- `carrick.native-kernel-transition-census.v1`; and
- `carrick.native-kernel-transition-comparison.v1`.

No Python or standalone shell parser is an authority. Rust owns capture
validation, snapshot joining, kernel normalization, classification,
aggregation, comparison, and report generation.

## 6. Capture authority

### 6.1 Frozen launch determinants

Before launch, the profile rejects anything other than the exact native run
shape and records:

- clean Git HEAD and dirty-state verdict;
- capture executable path, SHA-256, Mach-O UUID, code-signature/entitlement
  identity, and DOF presence;
- D program bytes, SHA-256, profile schema, and sampling frequency;
- host model, architecture, page size, product version, OS build, Darwin kernel
  version/UUID, and boot-session UUID;
- KDK kernel executable and dSYM paths, content identities, UUID/build/arch
  match, and SHA-256 digests;
- exact image digest, target argv, argv SHA-256, allowed environment, and native
  backend semantics;
- persistent translation-store normalized-content receipt and workload
  determinant receipt; and
- birth and terminal launch-qualification receipt hashes.

Unknown ambient `CARRICK_*` variables fail before launch. Output paths, run ID,
PIDs, timestamps, and per-capture receipt paths are provenance, not target-argv
determinants.

### 6.2 Sampling population

The profile samples at 997 Hz, matching NativeShape's current direct all-CPU
denominator. Every tick for an admitted live process contributes exactly once
to one of:

```text
all_cpu = user_cpu + kernel_cpu + invalid_cpu
kernel_cpu = kernel_named_syscall + kernel_mach_trap + kernel_non_syscall
```

`invalid_cpu` includes a sample that cannot be assigned a legal user/kernel
mode or identity. It is never discarded. An accepted capture requires
`invalid_cpu == 0`.

The existing balanced BSD-syscall and Mach-trap state machine classifies each
kernel sample at sample time. Every entry must close by return or an explicit
thread/process terminal transition. Simultaneous syscall and Mach-trap state,
an unknown function state, or an open nonterminal state rejects the capture.
This makes `kernel-non-syscall` the same category as the stable native-wall
population being investigated rather than a new convenient denominator.

For every `kernel-non-syscall` sample, DTrace aggregates:

```text
(process_birth_key,
 image_generation,
 runtime_epoch,
 kernel_pc = arg0,
 pre_transition_user_pc = uregs[R_PC]) -> sample_count
```

The profile records named-syscall and Mach-trap counts for reconciliation but
does not use their transition-PC rows to select this campaign's candidate.
User samples are counted for the all-CPU denominator; this profile does not
replace NativeShape's per-user-PC census.

### 6.3 Exact fault populations

The same D program aggregates exact `vminfo:::as_fault` counts as:

```text
(process_birth_key,
 image_generation,
 runtime_epoch,
 pre_transition_user_pc = uregs[R_PC]) -> as_fault_count
```

`zfod`, `cow_fault`, page-in, protection, and any other explicitly supported
outcome are independent populations. `zfod` and COW are not subtracted from or
added to `as_fault` as if the probes partitioned one logical event. This profile
retains their exact count totals, and may retain a `zfod` PC table only if a
red-first live fixture proves that its `uregs[R_PC]` contract is identical and
the added cardinality stays lossless. COW remains count-only because its
private address argument is not qualified.

The existing native-fault provider qualification for this exact OS build and
boot must pass before launch. That qualification authenticates provider
activity and private argument semantics; the new profile additionally proves
the documented `uregs[R_PC]` transition-PC join in its own fixture.

All tracked fault events reconcile:

```text
all_as_fault = pc_keyed_as_fault + explicit_unresolvable_transition_as_fault
```

An accepted primary capture requires the explicit unresolvable transition
population to be zero. Fault rows are never sampled, top-N truncated, or
silently discarded.

### 6.4 Process, fork, exec, and epoch identity

The raw identity is the established immutable `ProcessBirthKey`:

```text
(pid, pr_start_tv.tv_sec, pr_start_tv.tv_usec)
```

The initial target publishes birth before samples are accepted. Children are
admitted only by `proc:::create`, with a parent birth key and fork frontier.
Successful exec increments `image_generation`; failed exec restores the prior
image state. Runtime JIT-catalog epochs nest beneath the process image and
reset/replay according to the existing NativeShape authority.

Fork events may precede the child's first runtime announcement. The D program
uses a typed pending-fork identity and emits the parent snapshot/catalog
frontier. Offline validation binds pre-announcement child samples and faults to
the observed child birth and inherited frontier. A child that exits before a
unique birth/frontier binding can be established rejects the capture; its work
is not assigned to the parent or dropped.

Epoch zero is explicit. A transition before the first ready JIT epoch may
resolve to an authenticated host image, but it cannot be retroactively assigned
to a later JIT mapping at the same address. Unknown/reused/retired birth keys,
image drift, runtime-epoch gaps, fork-frontier gaps, or post-exec rows under an
old generation are fatal.

### 6.5 Natural completion and loss

The target must exit naturally with rc 0 and exactly one workload success
marker. Every admitted descendant must retire and the live set must reach zero.
The trace must end on its own; aborting the DTrace consumer is not accepted
because fasttrap detach can kill a continuing native guest.

The dedicated capture receipt records every DTrace interruption, principal
buffer drop, aggregation drop, dynamic-variable drop, speculation drop,
speculation-busy drop, and stack-string drop. Any nonzero field rejects the
capture. Zero raw output, zero CPU samples, zero non-syscall kernel samples,
bounded fallback, abnormal completion, survivors, incomplete snapshots, or a
failed workload marker also reject it.

## 7. User transition-PC authority

### 7.1 One shared resolver

The implementation factors NativeShape's strict snapshot-manifest loader,
birth/image/epoch model, fork-ancestry join, and PC-range resolver into one
shared Rust module. NativeShape must continue to regenerate its already
accepted v3 census byte-for-byte from the same fixtures after the refactor.

Snapshot files remain immutable per `(pid, process birth, image generation,
runtime epoch, block)`. The manifest authenticates every file path, length,
SHA-256, range, generation, ancestry relation, and final block count. A sampled
or faulting PC joins the snapshot that was live for its event identity, not the
last snapshot written by a PID.

### 7.2 Mutually exclusive resolution

Every pre-transition user PC receives exactly one top-level resolution:

1. `own-jit` — exactly one block in the process image's snapshot;
2. `inherited-jit` — exactly one block inherited through the validated fork
   frontier;
3. `carrick-image` — exact range in the capture binary's Mach-O image catalog;
4. `darwin-image` — exact range in another authenticated Mach-O image;
5. `unresolved`; or
6. `invalid` — zero, noncanonical, misaligned, or otherwise illegal as a user
   instruction PC.

JIT range joins precede Mach-O image ownership because the cache is anonymous
`MAP_JIT`. Multiple JIT matches, multiple image matches, an own/inherited
conflict, or an event in a retired mapping rejects the census. Accepted primary
captures require `unresolved == 0` and `invalid == 0` for both non-syscall CPU
rows and exact `as_fault` rows.

### 7.3 JIT instruction classification

For a JIT PC, the census reads the exact four-byte AArch64 word from the joined
snapshot and uses NativeShape's Rust classification precedence. It reports:

- snapshot identity and module-relative instruction offset;
- exact instruction word and disassembly;
- NativeShape family;
- complete context operands when applicable;
- evidence semantics (`inserted-exact`, `exact-ambiguous`, or
  `guest-descriptive`); and
- the emitter/source audit status.

An `inserted-exact` label is not automatically removable. An exact trusted
transfer or context access may implement a required guest invariant. Conversely,
an `exact-ambiguous` or guest-descriptive word cannot select a Carrick patch
merely because it is frequent. The carry gate in section 11 remains mandatory.

### 7.4 Host instruction classification

For a Mach-O PC, the census records image UUID, image-relative offset, exact
instruction bytes, symbol/range when available, and Rust source location only
when it can be bound to the frozen capture source. ASLR addresses are preserved
as provenance but normalized offsets are comparison keys. A dylib leaf cannot
be relabeled as its presumed Carrick caller.

## 8. Kernel-PC authority

### 8.1 Live overlay and KDK binding

After DTrace stops naturally but before the live symbolizer handle is released,
the existing post-stop callback obtains a sampled-kernel overlay for every
distinct kernel PC. The requested and resolved address sets and their SHA-256
digests must reconcile with the raw population. A missing or raw-address-only
lookup rejects the capture.

The offline census then binds that live overlay to the caller-supplied KDK:

1. kernel product/build/architecture/UUID must match the capture authority;
2. at least two unambiguous exported anchors derive the same KASLR slide;
3. subtracting that slide must place every sampled PC inside the exact KDK
   executable text range;
4. the four-byte word at every normalized PC is read from the authenticated KDK
   Mach-O image; and
5. the dSYM contributes all public and local symbol ranges that contain or
   alias that address, plus DWARF source location when present.

One anchor, inconsistent slides, UUID/build drift, a PC outside text, missing
bytes, or a KDK/dSYM mismatch rejects the census. The implementation is Rust;
manual `nm`, `otool`, or `lldb` transcripts may qualify the design but are not
the published authority.

### 8.2 Alias-safe report

The stable kernel comparison key is:

```text
(kernel_uuid, normalized_text_offset, exact_instruction_word)
```

The report also includes live PC, normalized KDK address, enclosing symbol
ranges, every same-address alias, selected display name, offset, disassembly,
and source line when available. The display name is descriptive. It cannot
merge rows, select a patch, or override exact address/byte evidence.

The qualification fixture must include the known deferred-interrupt landing PC
and prove that the report shows the instruction after `msr DAIFClr, #0x7` plus
its alias set. A regression that again interprets this PC only as
`ml_set_interrupts_enabled_with_debug+0x4c` fails red-first.

## 9. Typed raw and capture receipts

`NKTRANS1` is line-oriented and deterministic. At minimum it contains:

- authority header and digest;
- target birth, child create/inherit, exec, runtime-epoch, and terminal records;
- exact CPU totals and keyed non-syscall joint rows;
- exact fault totals and keyed `as_fault` transition-PC rows;
- snapshot manifest identity;
- kernel-symbol overlay identity;
- lifecycle, workload, completion, and live-set reconciliation; and
- the seven-field interruption/drop object.

Every aggregate key and count is checked for overflow. Key order is stable and
the stream ends with a count/checksum terminator. The parser rejects unknown,
duplicate, missing, out-of-order, truncated, mixed-schema, or
total-inconsistent records.

`--summary-jsonl` writes exactly one dedicated capture receipt. An accepted
receipt includes the complete authority, raw/snapshot/kernel-overlay hashes,
all population counts, every arithmetic verdict, completion state, and an empty
ordered `evidence_errors` array. A post-launch failure writes a rejected receipt
when it can do so safely and exits nonzero. A rejected receipt never becomes
input to the census.

Receipt acceptance proves capture integrity, not performance or workload
equivalence. The campaign controller separately admits captures to a pair.

## 10. Census and comparison

### 10.1 Single-capture census

`carrick debug native-kernel-transition-census` authenticates the capture
receipt, raw trace, D program, snapshot manifest/files, live kernel overlay,
KDK/dSYM, capture binary, and census binary. A later parser or classifier can
re-analyze old raw evidence only by recording its new source and binary
identity.

The v1 census contains:

- exact all/user/kernel/invalid CPU populations and direct all-CPU shares;
- exact kernel named-syscall/Mach-trap/non-syscall populations;
- every exact joint `(kernel location, transition location)` row without top-N
  truncation;
- normalized transition-owner rows with exact member rows and disjointness
  checks;
- exact `as_fault` PC rows and separate fault-outcome totals;
- own/inherited JIT and host-image resolution coverage;
- kernel KDK-byte/symbol/source coverage;
- source-audit and evidence-semantics fields; and
- every provenance, arithmetic, lifecycle, and loss verdict.

Each CPU row reports:

```text
share_of_non_syscall_kernel = row_cpu_samples / kernel_non_syscall
share_of_all_cpu = row_cpu_samples / all_cpu
```

Each exact fault row reports its event count, share of all tracked `as_fault`,
and distinct process/image/epoch cardinality. These fault shares are displayed
beside matching normalized transition owners, but never inserted into a CPU
formula.

### 10.2 Normalized transition owners

Raw PCs differ across processes and captures. The census therefore retains raw
rows and may additionally group only under stable, source-auditable keys:

- host code: `(image UUID, image-relative offset, exact word)`;
- kernel code: `(kernel UUID, text-relative offset, exact word)`; and
- JIT code: exact instruction word plus complete NativeShape family/operand
  identity and one audited emitter/source mechanism.

No default grouping combines different kernel PCs, different host source
locations, exact-ambiguous guest occurrences, or several distinct emitter
mechanisms merely to cross 10%. A broader explicit group is legal only after a
source audit proves that its members are non-overlapping manifestations of one
removable source mechanism; every member remains listed and sums exactly to the
group.

### 10.3 Paired comparison

`carrick debug native-kernel-transition-compare <A> <B>` consumes two accepted
v1 censuses and emits the comparison schema. It requires equality of source,
signed binary, host/boot, OS/kernel/KDK identities, D program, schemas,
sampling frequency, image digest, exact target argv, environment, workload
receipt semantics, and persistent-store normalized content. Run IDs, birth
keys, timestamps, raw hashes, receipt hashes, and snapshot manifests must be
distinct.

The comparison reconstructs every exact total from each arm and reports shares
and absolute percentage-point drift for each kernel row, transition row, joint
row, and audited source group. A CPU group crosses the mechanical gate only
when:

```text
A share_of_all_cpu >= 0.10
B share_of_all_cpu >= 0.10
abs(A share_of_all_cpu - B share_of_all_cpu) <= 0.05
```

The comparison reports fault counts and drift independently. It never requires
a fault-share threshold for a CPU candidate and never promotes a high fault row
whose CPU share misses the gate.

## 11. Carry, stop, and implementation authority

A mechanical crossing is not a production candidate. It may be carried into a
separate optimization design only when source audit proves all of the
following:

1. the exact members map to one source-distinct Carrick mechanism;
2. the mechanism accounts for at least 10% of all sampled CPU in each capture;
3. no member overlaps another carried or already-closed mechanism;
4. the observed transition instruction is Carrick-authored/removable rather
   than required guest work or an address-only coincidence;
5. removing or compacting it preserves guest register, memory, fault, signal,
   fork, exec, publication, and recovery semantics;
6. the change does not add an ordinary-path tax or a permanent second runtime
   path; and
7. it remains useful for dynamic/JIT-on-JIT execution even if eager translation
   is implemented later.

Exact `as_fault` alignment with the CPU owner strengthens the mechanism finding
and supplies a predeclared counter for a later spike. Absence of such alignment
does not let the CPU row be called fault cost; it requires another mechanism
probe or closes that interpretation.

If a dominant transition row is guest-only load/store/fill work, diffuse across
unrelated source mechanisms, or removable only by weakening guest-visible
semantics, the result is `STOP`, not permission to patch around the gate. If no
source group survives all seven checks, the kernel-transition line closes and
the campaign moves to the next independently sized bucket.

Any carried mechanism receives its own approved design, red-first correctness
proof, normal-path implementation with an explicit control, traced mechanism
check, and untraced same-workload retention campaign. Retention authority is at
least eight counterbalanced ABBA quads. Only a later serialized Carrick-then-
Docker refresh can change the official 10.1776x score.

## 12. Qualification and measurement protocol

### 12.1 Red-first qualification fixture

The existing `conformance-probes/src/bin/bigallocfree.rs` is the launch-time
mechanism fixture. `CARRICK_TEST_SIZE_MB` and `CARRICK_TEST_ITERS` are set high
enough to create a large, known anonymous first-touch population. The probe's
`Vec::resize` touches every page and must end with exactly one `bigalloc=OK`.

Before the profile can measure the primary workload, the fixture must prove:

- natural completion and zero survivors/drops;
- a distinct child birth/image/runtime identity where applicable;
- exact CPU and fault population reconciliation;
- 100% transition-PC resolution across JIT and host images;
- correct own/inherited snapshot selection;
- a dominant JIT store/fill transition classification for its declared touch
  phase;
- matching exact `as_fault` activity without claiming that count as CPU; and
- alias-safe KDK normalization including the deferred-interrupt landing-PC
  regression fixture.

Tests first corrupt or omit birth keys, fork frontiers, snapshots, kernel
anchors, KDK bytes, PC alignment, totals, and aliases and prove the old/invalid
artifact fails. A green qualification validates the tool, not the performance
campaign.

### 12.2 Primary captures

Take two new quiet-box captures serially from one clean, frozen, freshly signed
binary. Both use the approved digest-pinned cold Go-build command, empty cold
`GOCACHE`, identical persistent translation-store normalized content, and the
same workload receipt. Docker does not run concurrently. Each run gets unique
artifact paths and a scoped Carrick run ID; cleanup proves zero survivors before
the next run.

The capture is attribution-only. Its elapsed time, user CPU, and system CPU may
be reported as observer diagnostics but cannot be compared with the official
untraced lane. A retry creates a new immutable rejected/accepted artifact; it
does not overwrite or resume a partial capture.

### 12.3 Decision output

After independently regenerating and hash-checking both censuses, the paired
comparison emits exactly one of:

- `CARRY`: one or more mechanically crossing rows exist, followed by an ordered
  source-audit table that names which single highest-ranked source mechanism may
  receive a separate design;
- `STOP`: no mechanically crossing source-distinct removable mechanism exists;
  or
- `INVALID`: authority, coverage, stability, or reconciliation failed and no
  opportunity conclusion is allowed.

If several non-overlapping mechanisms clear 10%, the report keeps all of them
as a ranked portfolio but authorizes work on only the largest current item.
After any retained optimization, attribution is refreshed before the next item;
the original shares are not compounded into a performance promise.

## 13. Testing and verification

Implementation is red-first and must cover:

1. profile vocabulary, CLI constraints, sudo reconstruction, D-program hashing,
   clean-source/binary authority, and exact native-target parsing;
2. D compiler contracts for `uregs[R_PC]`, `arg0`, tracer exclusion,
   process-tree admission, balanced syscall/Mach state, and natural completion;
3. strict `NKTRANS1` ordering, unknown/duplicate/missing/truncated records,
   checked overflow, every arithmetic reconciliation, and zero samples;
4. each DTrace interruption/drop counter independently rejecting a capture;
5. PID reuse, birth-key collision, fork prebirth binding, inherited frontier,
   exec success/failure, epoch zero, runtime replay, and terminal closure;
6. raw/snapshot/receipt substitution, manifest hash/range/block errors, own
   versus inherited ambiguity, and post-exec retired mappings;
7. zero/noncanonical/misaligned transition PCs and host/JIT/unresolved
   classification precedence;
8. NativeShape fixture parity after factoring the shared snapshot resolver;
9. exact JIT word/family/operand classification and source-semantics labels;
10. KDK UUID/build/arch mismatch, one/inconsistent slide anchors, text-range
    escape, missing instruction bytes, local/public alias sets, and the known
    deferred-interrupt landing-PC regression;
11. exact `as_fault` PC totals, independent fault-outcome totals, and rejection
    of any mixed CPU/fault denominator;
12. deterministic census regeneration, comparison determinant drift, duplicate
    captures, percentage-point stability, and exact 10% boundary cases; and
13. source-group non-overlap and rejection of groups formed only to cross the
    opportunity threshold.

Before primary evidence use, the implementation must pass focused CLI/runtime
tests, formatting, Clippy with warnings denied, `RUST_TEST_THREADS=1 just ci`, a
fresh signed build, the applicable native smoke gate, and the live
`bigallocfree` qualification. The implementation plan may add narrower gates
but may not weaken these.

## 14. Component boundaries and delivery

The implementation plan should keep four reviewable units:

1. **Shared transition identity:** factor NativeShape snapshot/ancestry/PC
   resolution behind one Rust module with parity tests and no schema drift.
2. **Trace authority:** add `NativeKernelTransition`, the durable D program,
   strict raw parser, capture authority, receipt, and live kernel overlay.
3. **Offline authority:** add KDK normalization, alias-safe exact-byte records,
   census, comparison, and source-group validation in Rust.
4. **Live evidence:** qualify with `bigallocfree`, take two primary captures,
   publish the comparison, and durably record `CARRY`, `STOP`, or `INVALID`.

No production optimization belongs in those commits. A carried result starts a
new design. The profile remains a reusable Carrick diagnostic because the same
transition-PC question applies after later optimizations and to dynamic code.

## 15. Failure and redesign conditions

- Stop if `uregs[R_PC]` fails the live qualification or cannot be bound across
  fork/exec without ambiguity.
- Stop if high-cardinality exact fault aggregation produces any DTrace loss;
  do not sample or truncate fault rows to obtain a plausible result.
- Stop if the live kernel overlay cannot be bound to exact matching KDK bytes
  for every non-syscall kernel PC.
- Stop if snapshot publication or ancestry cannot resolve every candidate row;
  do not assign unresolved PCs to the largest nearby range.
- Redesign if JIT mappings become mutable/unloaded or address reuse invalidates
  immutable snapshot semantics.
- Escalate a disputed individual mapping, register, or process state to the
  guest process through LLDB/core and the always-on event ring. That evidence
  explains mechanism; it does not replace the complete CPU census.
- If tracing changes the workload topology, completion, or fault behavior,
  reject the capture and design a lower-perturbation corroboration path. Do not
  use traced timing as a substitute.

## 16. Success criteria

This design is complete when Carrick can produce two accepted, independently
regenerable native-kernel-transition captures for the frozen cold-build binary
such that:

- every CPU and fault population reconciles exactly;
- every non-syscall CPU transition PC and exact `as_fault` PC resolves to one
  authenticated host image or own/inherited JIT snapshot;
- every kernel PC binds to exact matching KDK bytes with aliases preserved;
- the comparison expresses each stable transition owner's direct share of all
  sampled CPU without importing another artifact's ratio; and
- source audit either authorizes one non-overlapping, non-regrettable >=10%
  mechanism for a separate design or closes the bucket with no runtime patch.

Neither outcome completes the active performance goal. The campaign continues
until retained untraced work brings the shipped-default cold build to at most
3x Docker, then toward the project's 2x bar.
