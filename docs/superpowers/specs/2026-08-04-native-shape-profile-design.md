# Authenticated NativeShape Profile Design

**Date:** 2026-08-04

**Status:** approved architecture; implementation not started

**Scope:** Darwin/AArch64 native DSR cold-build attribution only

## Purpose

The accepted current-retained-tree `native-wall` pair leaves translated JIT
execution as the next stable unsplit bucket at 25.8818% / 25.3278% of all
sampled CPU. The existing `scripts/dtrace/native-shape-census.d` plus
`carrick debug jit-shape-census` mechanism can decode sampled JIT words, but it
is not evidence authority:

- the generic `--script` path does not authenticate the D program or launch;
- the `SHAPE1` stream has no capture authority or typed DTrace-loss receipt;
- the offline command imports a JIT share measured elsewhere instead of using
  one same-instrument CPU population;
- the capture does not bind source, binary, image, command, run ID, raw trace,
  snapshots, and classifier into one provenance chain; and
- the active Python classifier and the Rust classifier offer two answers.

This design replaces that workflow with a first-class `native-shape` trace
profile, a dedicated fail-closed capture receipt, and a Rust-owned census and
two-run comparison. It answers one question: after excluding already-closed
emitted-code lines, does one remaining source-distinct instruction shape
represent at least 10% of end-to-end sampled CPU in two independent captures?

This diagnostic does not select or implement a lowering. Traced wall time is
not product timing authority. Any carried shape receives a separate design,
correctness proof, and untraced ABBA campaign.

## Decision and alternatives

### Chosen: first-class profile plus Rust receipt and census

Add `TraceProfileKind::NativeShape`, bundle the durable D program, replace
`SHAPE1` with one strict authenticated protocol, capture kernel and user CPU in
the same instrument, bind the retirement snapshots, and extend the existing
Rust JIT census. This follows Carrick's established native-profile authority
model and leaves one typed answer.

### Rejected: retain generic `--script` and add an external manifest

An immutable manifest could bind every current artifact without changing
`carrick trace`. It would remain a second orchestration path outside the profile
type system, duplicate validation already present in Carrick, and make future
captures depend on an operator assembling the complete determinant set.

### Rejected: add shape rows to `native-wall`

`native-wall` is a high-perturbation kernel, syscall, stack, off-CPU, and wall
profile. Adding JIT-PC cardinality and snapshot orchestration would couple two
independent attribution questions and make the lighter emitted-shape instrument
pay the broad profile's perturbation. The two profiles may corroborate broad
shares, but they remain separate authorities.

## Scope and invariants

The implementation must preserve these boundaries:

- Default runtime behavior and emitted bytes remain unchanged. Snapshot export
  remains opt-in through the existing retirement seam.
- No `copyin` of live JIT instruction bytes is introduced. The prior copyin
  shape killed the native guest 2/2 times; authenticated retirement snapshots
  remain the byte authority.
- The profile follows the complete Carrick process tree and excludes the
  in-process DTrace consumer itself.
- Every accepted count comes from one 997 Hz instrumented run. Family shares of
  all CPU are direct ratios, not projections from another capture.
- Missing, duplicate, ambiguous, lossy, bounded, dirty, or incomplete evidence
  fails closed. Zero events is an error.
- A crash is a rejected capture. This design intentionally supports the
  user-approved export-only path; it does not add core-file snapshot recovery.
- `SHAPE1`, `carrick.jit-shape-census.v1`, and the external
  `--jit-share-of-total` input are replaced rather than retained as compatibility
  paths.
- Python owns no parsing, classification, comparison, or evidence decision.
- Eager full-image translation remains deferred. Incremental augmentation is
  still required for JIT-on-JIT code. Tier D remains default-off.

## Operator interface

An accepted capture uses one typed command:

```text
carrick trace \
  --profile native-shape \
  --trace-out A.raw.trace \
  --summary-jsonl A.capture.jsonl \
  --native-shape-snapshots A.snapshots \
  -- run --exec-backend native ... \
  image@sha256:<digest> <cold-build-command>
```

For `native-shape`, all three output arguments are mandatory. The raw and
receipt paths must differ. The snapshot path must not exist; Carrick creates it
for the original trace user, forwards it to the child as
`CARRICK_DSR_CODE_SNAPSHOT_DIR`, and rejects a nonempty or substituted path.
Other profiles do not accept `--native-shape-snapshots`.

The target is deliberately restricted to a Darwin/AArch64 `run` invocation
with explicit `--exec-backend native` and a digest-pinned image. Carrick parses
the target invocation structurally; it does not identify the image by scanning
arbitrary command strings. `CARRICK_RUN_ID` is generated before the sudo
re-exec when absent, forwarded unchanged, and recorded. A caller-supplied ID is
accepted when nonempty.

The offline census becomes:

```text
carrick debug jit-shape-census A.raw.trace \
  --capture A.capture.jsonl \
  --snapshots A.snapshots \
  [--output A.census.json]
```

The old `--jit-share-of-total` argument is removed. A paired comparison is:

```text
carrick debug jit-shape-compare A.census.json B.census.json \
  [--output comparison.json]
```

All JSON outputs are deterministically ordered and atomically published.

## Capture authority and data flow

### Preflight and raw authority

Before launching the workload, Carrick:

1. requires a clean, known Git HEAD;
2. hashes the exact running executable;
3. records the Darwin build and host identity;
4. validates the digest-pinned image and exact native target argv;
5. computes a length-delimited SHA-256 of that argv;
6. qualifies the existing native launch birth/terminal provider environment;
7. hashes the immutable bundled D template; and
8. creates a canonical `NativeShapeAuthority` containing those determinants
   plus the run ID.

The rendered D program emits one `NSHAPE2|header` carrying the profile, raw
schema, OS build, D-template SHA-256, launch-qualification receipt hashes,
sampling frequency, and SHA-256 of the canonical capture authority. The
receipt contains the full authority object. Parsing recomputes its digest and
requires an exact header match. The template hash, rather than the substituted
program hash, avoids self-reference and matches Carrick's existing native
profile convention.

The authority digest is SHA-256 over `serde_json::to_vec` of one fixed-field
Rust struct in declaration order. It contains no maps, optional fields, or
floating-point values. Command argv uses its own length-prefixed byte encoding
before hashing, so argument boundaries cannot collide.

After the trace stops, Carrick recomputes Git and binary identity. Drift or a
dirty tree rejects the capture.

### D program and strict raw protocol

`scripts/dtrace/native-shape-census.d` is replaced in place; no second shape D
program is added. Its durable header continues to document provider ABI facts
and high perturbation. The new protocol prefix is `NSHAPE2`, with raw schema
`carrick.native-shape.raw.v2`.

The wire order is exact: header first, zero or more fork/exit lifecycle rows
while the target tree runs, then the final sections and completion:

```text
NSHAPE2|header|profile=native-shape|raw_schema=...|...authority fields...
NSHAPE2|fork|parent=<u32>|child=<u32>
NSHAPE2|exit|pid=<u32>|reason=<i32>
NSHAPE2|section=mode
NSHAPE2|mode|kind=all|count=<u64>
NSHAPE2|mode|kind=user|count=<u64>
NSHAPE2|mode|kind=kernel|count=<u64>
NSHAPE2|mode|kind=invalid|count=<u64>
NSHAPE2|section=region
NSHAPE2|region|kind=jit|count=<u64>
NSHAPE2|region|kind=non-jit|count=<u64>
NSHAPE2|section=pc
NSHAPE2|pc|pid=<u32>|pc=0x<u64>|count=<u64>
NSHAPE2|complete|bounded=<0|1>|target_completed=<0|1>|target_exit_reason=<i32>|target_pid=<u32>|admitted=<u64>|exited=<u64>|live_at_end=<u64>|probe_errors=<u64>
```

Each mode and region row occurs exactly once; at least one PC row is required.

The profile tracks `$target` plus descendants admitted by `proc:::create`,
inherits cache bounds across fork until the child publishes its own
`dsr-cache-bounds`, and records each parent/child link plus one exit row per
tracked process. Per-CPU-safe aggregations authoritatively maintain admitted,
exited, live-process, and probe-error counts. A scalar `live_hint` exists only
to decide when to request exit and is never evidence: an early racy zero is
rejected by aggregate/graph reconciliation, while a late value reaches the
180-second bound and is rejected. Target completion/reason and bounded remain
single-event scalars. Target exit does not normally end the trace until the
hint observes every tracked descendant gone.

An independently aggregated `all_cpu` count receives every tracked
`profile-997` firing. That one population is then divided as follows:

- only `arg1 != 0`: user CPU; further divided into exact JIT and non-JIT
  regions;
- only `arg0 != 0`: kernel CPU; and
- both or neither PC present: invalid CPU, which must be zero for acceptance.

Every JIT user sample contributes to a `(pid, pc)` histogram. The strict stream
contains exactly one header, mode totals, region totals, PC section, and
completion. Its required reconciliations are:

```text
all_cpu = user_cpu + kernel_cpu + invalid_cpu
invalid_cpu = 0
user_cpu = jit_user + non_jit_user
jit_user = sum(pc rows)
```

The completion record requires natural target completion, the qualified normal
exit reason, a unique rooted tree at `target_pid`, and complete aggregate/row
reconciliation. Every fork parent must be reachable from the target, every
admitted PID has exactly one exit row, every exit and PC PID is admitted, the
target exit row agrees with the completion reason, `admitted` equals the rooted
vertex count, `exited` equals the unique exit count, and
`live_at_end == admitted - exited == 0`. Probe errors are zero. DTrace's six
numeric drop classes plus `interrupted` come from the runtime
`DTraceRunReport`; every numeric field must be typed zero and `interrupted`
must be literal false.

The parser accepts only the exact field sets and record order defined by this
schema. It rejects old `SHAPE1`, unknown `NSHAPE2` records, duplicate fields,
zero PC rows, arithmetic overflow, and any reconciliation failure.

### Snapshot authority

The existing `carrick.code-snapshot.v4` JSON/`.bin` pairs remain the instruction
byte authority. The profile uses a fresh dedicated directory. Snapshot loading
is strengthened to reject subdirectories, symlinks, unknown files, incomplete
pairs, wrong schemas, length or digest mismatches, unaligned or overflowing
ranges, and overlapping same-PID resolving ranges. Within one real directory,
the same recognized extension plus the same stem implies the same filename, so
it cannot appear twice; same-stem `.json`/`.bin` entries are instead the
required pair.

One shared Rust snapshot module computes a deterministic manifest over each
sorted stem, metadata digest, and payload digest, using NUL separators between
fields and a newline between records. Both the capture receipt and the census
call that implementation. The census recomputes the manifest and requires it
to equal the receipt. A sampled PID must have an authenticated snapshot. A PC
resolves to exactly one own range, or—only when the child has its own
authenticated snapshot—to exactly one recorded ancestor range. Missing and
ambiguous joins are errors; accepted coverage is therefore 100% of JIT
samples.

Before marking the capture receipt accepted, the trace command runs that same
resolver over every raw PC row and requires 100% coverage. The census repeats
the check from the immutable artifacts before it classifies any word.

Snapshot-export warnings do not weaken this rule: any resulting missing pair or
sample fails the capture/census.

### Dedicated capture receipt

`--summary-jsonl` writes exactly one JSON line with schema
`carrick.native-shape-capture.v1`. It is not sent through the generic
`ProfileSummary` metric schema. The receipt includes:

- `outcome` (`accepted` or `rejected`) and ordered `evidence_errors`;
- full capture authority and its SHA-256;
- raw trace SHA-256 and strict raw schema;
- snapshot manifest SHA-256, pair/PID/block/byte counts;
- run ID, Git HEAD/dirty state, executable SHA-256, host, image, exact argv,
  and argv SHA-256;
- launch-qualification receipt hashes;
- all, user, kernel, JIT, non-JIT, invalid, and PC-row/sample counts;
- natural/lifecycle completion fields; and
- the exact seven-field DTrace interruption/drop object.

For any failure after the target was launched, Carrick writes a rejected
receipt when it can do so safely and exits nonzero. Preflight, D compilation,
or output-creation failures exit nonzero without claiming a capture receipt.
Fields that cannot be established after a rejected parse are null and named by
`evidence_errors`; an accepted receipt requires every field above and has no
evidence errors. Receipt acceptance proves capture integrity, not workload
success. The measurement controller separately requires successful command
completion and exactly one `BUILD_OK` before admitting a capture to the pair.

## Rust census and classification

`carrick debug jit-shape-census` first authenticates the capture receipt, raw
trace, D program, snapshot manifest, and every count reconciliation. It also
requires a clean, known census Git HEAD and hashes the executable running the
census, so later parser fixes or re-analysis remain explicit rather than
masquerading as the original classifier.

The output schema is `carrick.jit-shape-census.v3`. It contains:

- capture-receipt, raw-trace, snapshot-manifest, capture-binary, and
  census-binary identities;
- capture and census source identities;
- exact CPU populations and direct all-CPU shares;
- own/inherited JIT join coverage;
- mutually exclusive instruction-family rows;
- every exact `(family, instruction_word)` row without top-N truncation;
- exact context rows by direction and complete first/optional-second operands;
  and
- a separately labelled lower bound on sampled Carrick-authored/source-exclusive
  instruction words.

Classification precedence is deterministic. The Rust classifier absorbs the
active exact AArch64 families once split across Rust and the deleted Python
classifier: 64/32-bit and pair context traffic, generation guards,
aperture/window operations, bias operations, NZCV traffic, x17/x18
materialization, DSR-only x18 addressing, trusted transfers, and then coarse
guest branch/load-store/arithmetic/SIMD families. Exact encodings are divided
by evidence semantics: context 64/32/pair through physical x28, window
UBFM/CBZ through physical x18, x18 materialization, exact x17 trusted branch,
and x18-based loads/stores are `inserted-exact`; generation-guard LDAR, bias
ORR, NZCV MSR/MRS, and x17 materialization are `exact-ambiguous` because a
guest can produce the same instruction words. Coarse guest families are
`guest-descriptive`. The `inserted_exact_floor` field sums only
`inserted-exact` rows. It is a lower bound on sampled
Carrick-authored/source-exclusive instruction words, not an extra-instruction
count, removable-overhead claim, or projected speedup: an exact word such as
`br-x17` can still implement required guest semantics. Source audit remains the
carry gate.

Each context row counts one sampled instruction once. A single load/store has
one exact operand and no second operand. A pair decodes signed `imm7 * 8`, `Rt`,
checked first-slot `+ 8`, and `Rt2` into two exact operands on the same row.
Rows sort by the complete direction/operand key, and the validator reconstructs
that compound map from every exact word row so changing either operand fails
closed. The sum of context-row samples therefore remains equal to the union of
context-family instruction samples without dropping pair semantics.

Once Rust parity tests pass, `scripts/perf/shape_classify.py` is deleted. Old
historical reports remain immutable and retain their original authority.

Each family and exact-word row reports:

```text
share_of_jit = row_samples / jit_user
share_of_all_cpu = row_samples / all_cpu
```

No imported ratio, traced elapsed time, or Docker time enters the census.

## Paired comparison and carry rule

`jit-shape-compare` consumes two accepted v3 censuses and emits
`carrick.jit-shape-comparison.v1`. It requires the same capture source, signed
binary, D program, image digest, exact target argv, sampling frequency, and
classifier binary/schema. Run IDs, raw hashes, and snapshot manifests must be
different. It rejects duplicate captures and determinant drift.

The measurement commands therefore keep target argv byte-identical across A
and B; per-capture host run IDs and artifact paths stay outside target argv.
The cold-build command uses a fixed serially cleaned guest path rather than
embedding a capture ID.

The comparison reports both shares and absolute percentage-point drift for
every family, exact word, and context row. A row crosses the mechanical gate
only when it reaches at least 10% of all CPU in both captures and differs by no
more than five percentage points.

A mechanical crossing is not yet a production candidate. Before carry, source
audit must prove that the row or explicit non-overlapping group:

1. maps to one source-distinct removable emitter mechanism;
2. does not overlap already-closed context traffic, trusted-entry routing, or
   another selected row;
3. represents Carrick-inserted work rather than the guest's required
   instruction semantics; and
4. can be removed without weakening guest register, recovery, publication,
   generation, signal, or memory semantics.

If no row survives those checks, the emitted-shape line stops with no patch. If
one survives, it receives a separate design and one-hypothesis implementation;
retention authority remains an untraced same-workload ABBA with at least eight
counterbalanced quads.

## Component boundaries

The implementation keeps three units with distinct responsibilities:

1. **Trace/capture authority:** `TraceProfileKind::NativeShape`, bundled D
   program, authority rendering, strict `NSHAPE2` parser, and dedicated receipt.
2. **Snapshot/join authority:** one reusable Rust module for strict v4 snapshot
   loading, deterministic manifests, fork ancestry, and exact PC resolution.
3. **Census/comparison:** AArch64 word classification, deterministic v3 report,
   and paired comparison commands.

The existing `debug_jit_shape.rs` is refactored only enough to establish these
boundaries. Generic DSR/native-wall summaries remain unchanged. No unrelated
runtime or trace-profile refactor is in scope.

## Error handling

All evidence errors are named and nonrecovering. In particular:

- invalid target/backend/image or dirty/unknown source fails before launch;
- D compile failure, no raw output, or zero samples exits nonzero;
- bounded/abnormal completion, live descendants, probe errors, interruption,
  or any drop rejects the capture;
- provenance drift rejects the capture even when the workload prints
  `BUILD_OK`;
- snapshot/export or PC-join defects reject the receipt/census rather than
  forming missing buckets;
- receipt/raw/manifest mismatch rejects re-analysis;
- the census records any intentionally newer classifier identity; and
- classifier or other comparison determinant drift rejects the pair rather
  than reporting a plausible delta.

There is no retry inside the profile. The campaign controller decides whether a
fresh, separately named capture is warranted and preserves every rejected
receipt unchanged.

## Testing and acceptance

Implementation is red-first and must cover:

- profile vocabulary, CLI constraints, sudo reconstruction, bundled-template
  hashing, authority rendering, and exact native-backend/image parsing;
- D source contracts for tracer exclusion, process-tree tracking, inherited
  bounds, user/kernel/invalid sampling, no `copyin`, natural completion, and
  bounded fallback;
- strict `NSHAPE2` record ordering, unknown/duplicate/missing fields, every
  arithmetic reconciliation, lifecycle errors, and zero samples;
- each of the six DTrace drop counters plus interruption;
- pre/post Git and binary drift and authority-digest mismatches;
- strict snapshot directory/manifest/hash/range/ancestry cases;
- receipt/raw/manifest substitution and rejected-receipt handling;
- exact instruction encodings, classification precedence, Python-parity
  fixtures, context-row disjointness, and all-CPU arithmetic;
- deterministic census regeneration and two-run determinant/stability gates;
  and
- rejection of `SHAPE1`, v1/v2 census input, and the removed external JIT-share
  argument.

Before live evidence use, the implementation must pass focused CLI/runtime
tests, formatting, Clippy with warnings denied, `RUST_TEST_THREADS=1 just ci`, a
fresh signed build, and the applicable native smoke gate. One signed
qualification capture must then prove D compilation, authenticated header,
natural lifecycle closure, zero loss/errors, strict snapshot publication, and
100% JIT-PC resolution. That qualification is tool validation, not performance
attribution.

The measurement phase then takes two new quiet-box captures serially from one
frozen current-retained binary and exact digest-pinned workload. Their census
and comparison artifacts are regenerated independently and hash-checked before
any carry decision. Docker does not run concurrently and is not needed for
this attribution-only phase.

## Success criteria

This design is complete when Carrick can produce two accepted, independently
regenerable NativeShape captures whose reports directly express emitted-word
residency as a share of all sampled CPU, with no external ratio and no Python
authority. The result must either:

- name one non-overlapping source-distinct inserted mechanism at or above 10%
  in both captures and authorize a separate lowering design; or
- durably stop the translated-guest split with no implementation candidate.

Neither outcome changes the official 10.1776x scoreboard. Only a later retained
untraced candidate and serialized Carrick-then-Docker refresh can do that.
