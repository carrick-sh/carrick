# Exact Conformance and Native-Cost Closure

**Date:** 2026-08-16

**Status:** Approved design; controlling goal for this campaign

**Platform scope:** canonical macOS/HVF arm64 HVPatch lane only

## Goal

Make Carrick's canonical macOS/HVF arm64 HVPatch lane exactly conformant to
native-arm64 Linux across its frozen declared surface, then make that surface
run at native-shaped cost.

Completion requires all three boundaries to hold together on one final clean
integrated source revision and its exact signed binary:

1. the conformance gate is incapable of reporting the known false-green
   shapes as success;
2. every applicable assertion in the frozen suite and probe inventories is
   exercised and matches Linux semantics; and
3. the Go, CPython, Node, and LTP aggregate scoreboards plus cold `go-build`
   are each no more than **2.0x** native-arm64 Docker.

Any valid completing suite at or above **10.0x** Docker is a correctness
blocker. It indicates pathological lowering or algorithmic work and returns to
the correctness workflow. Timeout-duration ratios are not performance data;
the timeout remains a correctness failure.

Carrick may be rearchitected wherever evidence shows that the current model or
lowering cannot satisfy these boundaries.

## Paste-ready `/goal`

> On the canonical macOS/HVF arm64 HVPatch lane, first make the conformance
> gate fail closed and freeze the current 2,127-suite declared surface; then
> achieve 100% executed assertion-level parity with native-arm64 Linux across
> all applicable suites and arm64 musl/GNU conformance probes, with zero gaps,
> excuses, false matches, skips, crashes, timeouts, empty results, oracle
> failures, or retry-recovered acceptance. After correctness closes, bring the
> Go, CPython, Node, and LTP ecosystem aggregates plus cold `go-build` to no
> more than 2.0x native-arm64 Docker, treating every valid completing suite at
> or above 10x as a correctness blocker. Permit evidence-driven rearchitecture;
> require red-first deterministic reducers, Docker bpftrace ground truth,
> carrick trace/DTrace or lldb/core diagnosis, isolated subagent work,
> serialized authoritative Carrick/Docker measurements, exact signed-artifact
> provenance, and durable phase-boundary reports. Complete only when gate
> integrity, correctness, and performance all pass together on the final
> integrated artifact.

## Why the existing green gate is not the goal

The checked-in state at design time is not a credible correctness receipt:

- source HEAD: `f30cc58368c326c423e2937d688cbfc118245457`;
- generated manifest: 2,127 suites — 438 CPython, 194 Go, 3 Node, and
  1,492 LTP; 23 are smoke-tier and the full tier selects all 2,127;
- checked-in baseline/matrix: 2,064 rows — 1,977 `MATCH`, 43 `DIFF`, and
  44 `NEW`;
- manifest/baseline inventory drift: 72 manifest names absent from the
  baseline and 9 obsolete baseline names absent from the manifest;
- 1,128 current `MATCH` rows are shared LTP `TBROK` setup failures rather
  than exercised behavior;
- 10 manifest rows carry `known_gaps`;
- 455 probe source binaries exist, but the current runner includes helpers,
  performance programs, hard skips, missing-binary self-skips, and report-only
  libc/architecture sets.

Design-time artifact hashes:

| Artifact | SHA-256 |
| --- | --- |
| `scripts/conformance/suites.toml` | `36042b91814ca767d61a6615c0023aa07773b7f5649fc65038fae6c34367d282` |
| `scripts/conformance/baseline.jsonl` | `12d8021f478a07dbae78a7dcaad5df774fa36e402ffaf0842c405c87be7213f7` |
| `docs/support-matrix.md` | `025e3a56db70ca4d301d003c7d49a81c6433defb4118ba69b9d3e3f5737cbb18` |

These hashes describe the starting point. Phase A produces the authoritative
campaign inventory and immutable image/oracle identities.

## Scope and denominator

### In scope

- The canonical local `hvf` conformance lane. A lane selects where Carrick
  runs; HVPatch is the single backend.
- Every assertion-bearing case in the campaign-frozen 2,127-suite manifest.
- Every applicable arm64 musl and arm64 GNU conformance probe.
- Gate, parser, oracle, artifact-receipt, and performance-harness changes
  needed to make the completion claim falsifiable.
- Runtime, VFS, memory, scheduler, process, signal, networking, image, HAL, or
  architectural changes needed to close measured gaps or pathological cost.

### Outside this campaign

- Linux/KVM, FreeBSD/bhyve, and NetBSD/NVMM completion. They remain later
  matrix phases and neither dilute nor block this macOS goal.
- A claim of compatibility with the entire Linux syscall surface. The
  denominator is the frozen declared conformance surface, not all present and
  future Linux APIs.
- Retired `native` or `vmm` backend parity.

### Exclusions

A genuinely unavailable kernel facility may sit outside the denominator only
through a reviewed ledger entry containing:

- the exact suite, probe, and assertion identifiers;
- fresh native-arm64 Linux evidence;
- the missing host, kernel, privilege, or hardware prerequisite;
- proof that the case is unavailable rather than a Carrick failure;
- an owner and an objective re-entry condition; and
- the source and image version to which the decision applies.

An exclusion is reported separately. It is not `MATCH`, not a pass, and cannot
support an “all Linux” claim. `TBROK`, `TCONF`, `SKIP`, empty output, and oracle
failure cannot silently become exclusions.

## Governing invariants

1. **Correctness precedes performance.** Phase C cannot close until Phase B is
   green. A >=10x completing row moves back to Phase B because pathology is a
   correctness signal.
2. **Assertion identity is authority.** Aggregate counts and exit codes are
   insufficient when the underlying framework exposes assertion-level output.
3. **A missing result fails closed.** Missing suites, baseline rows, probes,
   binaries, oracle keys, raw files, or provenance are failures of proof.
4. **No inherited excuses.** `known_gaps`, baseline-pair excuses, report-only
   results, allow-hang state, retries, and first-observation `NEW` semantics are
   forbidden in a completion receipt.
5. **One artifact, one claim.** All final gates bind to one clean source HEAD
   and its exact signed Carrick binary.
6. **Carrick and Docker never overlap.** Oracle and Carrick phases are
   serialized, with scoped run IDs and cleanup.
7. **Evidence selects architecture.** Large redesigns are allowed, but a
   design is retained only after its mechanism, correctness, and performance
   claims survive their named proof gates.

## Phase A — Make the gate trustworthy

### Objective

Turn the current regression-against-baseline harness into a fail-closed
assertion-level completion instrument without losing its useful day-to-day
regression mode.

### Required red-first contracts

Add focused tests that first reproduce and then reject every known false-green
shape:

- a manifest row missing from the baseline or result inventory;
- an obsolete baseline row not present in the manifest;
- Carrick and Docker both failing or breaking setup;
- both sides `TCONF` or `TBROK`;
- equal summary categories with different assertion identifiers or counts;
- a `NEW`, `ORACLE_FAIL`, crash, timeout, or empty first observation that does
  not gate;
- a divergence excused by substring `known_gaps` or a prior baseline pair;
- an unknown lane spelling that falls through to HVF;
- a mutable image tag whose bytes changed without invalidating the oracle;
- a flake retry whose first non-gating attempt replaces a failure;
- an allowed hang that becomes non-gating after a bless;
- a missing probe binary, oracle, cache entry, or lane that self-skips;
- an applicable arm64 GNU probe classified as report-only;
- shell or TAP success whose assertion/output body diverges; and
- a source/binary freshness warning that does not invalidate the receipt.

### Harness outcome

Provide two explicit modes:

- **regression mode** may retain reviewed baseline behavior for ordinary
  development, but must state that it is not a completion receipt;
- **closure mode** enforces the requirements in this design and exits nonzero
  on any missing, skipped, excused, indeterminate, or non-passing assertion.

Closure mode must:

- require exact manifest, generator, baseline, matrix, selected-result, and
  oracle-key inventory equality;
- compare normalized LTP assertion identities and outcomes, not the synthetic
  one-row summary;
- parse applicable TAP assertions and validate shell output contracts;
- separate pass, fail, broken, configuration skip, exclusion, and
  infrastructure failure without folding them into parity;
- use image digests in oracle determinants and record raw-output hashes;
- reject retries and allow-hang state;
- reject missing binaries and report-only applicable probe sets;
- inventory each probe as `conformance`, `performance`, `helper`, or reviewed
  `exclusion`, and gate all applicable arm64 musl/GNU conformance probes; and
- emit a machine-readable receipt with all completion metadata.

### Phase A exit gate

- Every false-green contract is red before its fix and green afterward.
- The generator reproduces the checked-in manifest exactly.
- Inventory equality checks pass.
- The frozen campaign manifest, assertion inventory, image digests, oracle
  determinants, and probe inventory are recorded.
- `just ci` passes.
- A dated Phase A report records what is now prevented and the first honest
  Phase B denominator; it does not claim conformance progress from parser
  changes alone.

## Phase B — Close correctness

### Initial discovery run

Use the durable bootstrap and the closure-mode equivalents of:

```sh
scripts/conformance/run-full.sh --force --refresh-oracle
```

The harness must build and sign first, execute all Carrick cases, then execute
the native-arm64 Docker oracle. It must use no flake retries and retain every
raw output, run ID, argv, result, timeout classification, and cleanup receipt.

The discovery result is a backlog, not a baseline to bless. Cluster gaps by
mechanism rather than by test name when evidence supports a shared cause.

### Per-gap TDD and diagnosis loop

Every real gap follows this order:

1. Confirm that native-arm64 Docker exercises the intended assertion. Use
   `bpftrace` inside the Docker oracle for Linux syscall shape; do not use guest
   `strace` as oracle evidence.
2. Reduce the divergence to the smallest deterministic probe. The probe prints
   stable relationships or values, bounds every wait, and runs line-exact under
   Carrick and Linux.
3. Prove the reducer red on the exact pre-fix signed binary.
4. Attribute one mechanism before changing production code.
   - Use bounded `carrick trace`/DTrace with `progenyof($target)`, nonzero-event
     checks, drop checks, scoped run IDs, and a durable script for reproducible
     failures.
   - Use `carrick debug lldb-run`, the always-on event ring, all-thread stacks,
     and modified-memory cores for hangs or when tracing perturbs the bug.
   - Prefer dynamic tracing and postmortem evidence over added log lines.
5. Implement the smallest correct fix or the evidence-supported architectural
   change. Lower Linux operations onto the smallest correct Darwin primitive
   where that preserves Linux semantics.
6. Prove the reducer green, then the originating suite green, then the affected
   cluster green.
7. Run the proportionate host tests and `just ci` before integration.
8. Commit the reducer, durable trace/core analysis, implementation, and evidence
   in narrow logical changes.

### Subagent model

- Dispatch one subagent per independent failure cluster only after the initial
  evidence makes independence credible.
- Each implementation uses an isolated ignored `.worktrees/` checkout and
  preserves unrelated user changes.
- Subagents may create reducers, trace scripts, diagnoses, tests, and narrow
  commits. Their conclusions are leads until the coordinator revalidates them.
- The coordinator alone integrates changes and runs authoritative broad
  Carrick/Docker or performance measurements.
- Agents must not run Carrick and Docker concurrently or contaminate another
  agent's gate. Cleanup is always scoped by `CARRICK_RUN_ID`.

### Phase B exit gate

On one clean merged HEAD and its exact signed binary:

1. Run one exhaustive unfiltered closure pass with a fresh native-arm64 Docker
   oracle and no retries.
2. Run a second exhaustive unfiltered Carrick pass against that frozen oracle,
   using the same binary and no retries.
3. Run every identified timing-sensitive row three consecutive times in
   isolation.
4. Run the complete applicable arm64 musl/GNU line-exact probe surface.
5. Run `just ci`.

Machine assertions require:

- the exact frozen suite and assertion counts;
- every applicable assertion executed and passing Linux semantics;
- zero `DIFF`, `NEW`, `REGRESSION`, known gap, baseline excuse, report-only
  result, `TBROK`, `TCONF`, skip, empty result, crash, timeout, oracle failure,
  retry-recovered result, missing raw artifact, or unscoped leftover process;
- exclusions exactly equal to the reviewed outside-denominator ledger; and
- byte-identical provenance across all claimed gates.

## Phase C — Close performance

### Authoritative measurement mode

Parallel conformance timings remain diagnostics. Add or use an authoritative
serial performance mode that:

- performs a quiet-host preflight and fails closed on contamination;
- pins source, signed binary, manifest, images, commands, host/OS/hardware, and
  measurement implementation;
- runs Carrick and Docker arms serially and never concurrently;
- rejects timeouts, crashes, missing samples, dirty receipts, trace drops, and
  mismatched artifacts;
- reports per-suite measurements plus ecosystem aggregate totals; and
- retains raw measurements and a deterministic comparison artifact.

### Scoreboards

Collect at least five accepted paired samples for each:

- cold `go-build`;
- the complete Go aggregate;
- the complete CPython aggregate;
- the complete Node aggregate; and
- the complete LTP aggregate.

For an ecosystem aggregate, each arm is the sum of the same frozen set of
valid, assertion-bearing suite durations under serial execution. Exclusions
are absent from both numerator and denominator and are reported alongside the
score. The comparison tool computes each paired ratio, reports its median, and
computes the two-sided 95% percentile-bootstrap interval over paired ratios
with 100,000 resamples and a recorded fixed seed. Any future statistical-method
change versions the receipt and invalidates cross-version comparison.

### Phase C exit gate

- Every scoreboard median Carrick/Docker ratio is <=2.0.
- Every scoreboard's paired 95% interval upper bound is <=2.0.
- No valid completing suite remains >=10.0x in any accepted full measurement.
- A >=10x row is isolated and returned to Phase B; it cannot be averaged away
  or called a tuning opportunity.
- The final performance report binds to the same final source and signed binary
  provenance as the correctness receipt.

## Final receipt

The final evidence bundle records at minimum:

- clean source HEAD and ancestry;
- binary SHA-256, CDHash, LC_UUID, `com.apple.security.hypervisor`
  entitlement, and `__dof_carrick` presence;
- macOS build, hardware identity, toolchain, and relevant limits;
- manifest, assertion-inventory, generator, baseline, matrix, probe-inventory,
  image, oracle-key, and raw-output hashes;
- every exact command and environment determinant without secrets;
- all Carrick and Docker run IDs and proof of scoped cleanup;
- closure-mode result JSONL and assertion census for both exhaustive passes;
- the complete probe transcript and machine census;
- targeted three-run receipts for timing-sensitive cases;
- `just ci` output; and
- all performance samples, comparison statistics, and <=2x/>=10x assertions.

The receipt fails closed if any component is missing or belongs to another
artifact. A blessed baseline, generated matrix, green CI run, 100% probe result,
or intermediate performance win is not completion by itself.

## Progress reporting

Publish a durable report at each phase boundary and after every material
mechanism cluster. Each report states:

- exact source and binary provenance;
- current denominator and executed count;
- passes, real gaps, infrastructure failures, and reviewed exclusions;
- reducers and diagnostic artifacts added;
- architectural decisions retained or rejected and the evidence for each;
- current ecosystem and `go-build` performance only when the measurement is
  authoritative; and
- the next evidence-selected work item.

Progress is a reduction in honestly measured unexercised assertions, semantic
gaps, or pathological work. Moving a row into an exception, retry, skip, or
coarser parser category is not progress.

## Risks and controls

- **Campaign scope drift:** freeze hashes and counts; version any intentional
  scope change and rerun inventory gates.
- **Oracle drift:** use digest-bound images and a fresh final oracle; retain raw
  results and determinants.
- **Load-induced misdiagnosis:** keep broad measurements coordinator-owned and
  serial; reproduce suspect rows on the pre-change binary and in isolation.
- **Flake laundering:** no acceptance retries; require repeated isolated proof.
- **Trace perturbation:** use the event ring, lldb, and modified-memory cores
  when DTrace changes the manifestation.
- **Metric optimization:** require originating assertions and broad gates after
  every reducer; never optimize the verdict number alone.
- **Architectural sunk cost:** define each redesign's correctness and cost
  falsifiers before implementation and preserve negative evidence.

## Non-completion examples

The goal remains open if any of the following is true:

- all harness verdicts are non-gating but one is `DIFF`, `NEW`, skipped,
  broken, configured out, or inherited from the baseline;
- Carrick and Docker fail the same assertion or fail different assertions with
  equal counts;
- the probe test exits zero after skipping a binary or report-only set;
- correctness passes on one binary and performance passes on another;
- an ecosystem aggregate is <=2x while one valid suite remains >=10x;
- a timeout is reported as a large performance ratio;
- a full run used retries or a stale/mutable oracle;
- only an intermediate cluster, smoke tier, probe suite, or `just ci` is green;
  or
- the final run leaves unscoped Carrick processes or lacks exact provenance.
