# Conformance Contracts as Carrick's Engineering Standard

**Date:** 2026-09-19

**Status:** Proposed for review

**Scope:** Every change that can affect guest-visible behavior or its operational cost

## Intent

Carrick must not call an implementation conformant merely because it returns the
right value. A Linux-visible operation implemented with pathological copying,
polling, serialization, allocation, host calls, or asymptotic work is also
incorrect. Carrick's development process therefore treats observable semantics
and non-pathological operational complexity as one conformance obligation.

This design turns the VM-free kernel backend and the signed embed interface into
the primary development surfaces for that obligation. Docker remains the Linux
oracle, and full guest and ecosystem runs remain final integration evidence, but
most defects should be discovered and reduced below the CLI/ecosystem layer.

The design also makes this workflow a project engineering standard. It adds
normative documentation, a repository skill for agents, a machine-readable
contract registry, and mechanical ratchets that fail when guest-visible work
silently bypasses the required evidence.

## Success criteria

The program succeeds when:

1. every guest-visible change names an applicable conformance contract or adds
   one red-first;
2. the cheapest capable layer proves Linux semantics and deterministic work
   budgets together;
3. signed embed execution proves that the contract survives real guest memory,
   scheduling, signals, carrier lifecycle, and execution;
4. paired, same-image Docker measurements enforce the applicable runtime ratio;
5. structural, semantic, measurement, and timing failures all block promotion;
6. agents are instructed and mechanically ratcheted into this workflow; and
7. the first futex-contention contract proves the design vertically before the
   registry expands to other subsystems.

## Governing principles

### Performance pathology is a conformance failure

Carrick's conformance definition includes:

- Linux-visible values, errors, ordering, blocking, wakeups, and lifecycle;
- the expected complexity class and bounded resource amplification; and
- end-to-end runtime no worse than the accepted differential limit.

A semantic pass cannot excuse a structural-budget or runtime-ratio failure. A
valid completing case at or above 10x Docker immediately returns to correctness
triage. It is not queued as ordinary tuning work.

### Use the cheapest capable proof surface

The evidence ladder is additive:

1. compile-time ABI invariants;
2. VM-free kernel semantics and deterministic work budgets;
3. signed in-process guest execution through `carrick-embed`;
4. pinned same-image Docker differentials;
5. full CLI, probe, and ecosystem acceptance.

A higher layer adds evidence but cannot turn a lower-layer failure green. A
lower layer must not claim properties it cannot observe. In particular, the
VM-free backend does not prove guest instruction execution, stage-1/stage-2
mapping, signal-handler execution, or VMM integration.

### Structural budgets precede wall-clock budgets

The fast inner loop uses deterministic work counts: copies, bytes, allocations,
backend calls, queue visits, continuations, page-table edits, and similar units.
Wall-clock measurements are reserved for release-mode signed embed and ecosystem
comparisons where real execution costs are meaningful.

Instrumented timing is never cited as performance evidence. Uninstrumented
timing cannot compensate for a failed or incomplete structural measurement.

### Contracts are authored, not blindly blessed

Linux defines observable behavior. Carrick's intended architecture defines its
structural invariants. Measurement helps choose defensible coefficients, but a
budget must explain the correct algorithm rather than snapshot the current
implementation. Automatic refresh may update observations; it must never loosen
a budget.

## Architecture

### Component layout

The framework is development infrastructure and must not silently enter the
shipped product closure:

- a new dev/test-only `carrick-conformance-contract` crate owns descriptor
  parsing, observations, budget evaluation, typed failures, and receipt output;
- `conformance-contracts/contracts/*.toml` is the reviewed registry of contract
  metadata and budgets;
- `conformance-contracts/surfaces.toml` maps guest-visible source surfaces to
  contract families and drives the changed-path ratchet;
- `carrick-observability` owns the small execution-scoped work-meter vocabulary
  shared by the kernel and runtime; and
- layer-specific bindings remain beside their existing harnesses in
  `carrick-kernel-example`, `carrick-embed`, and `carrick-conformance-next`.

The new contract crate is excluded from the root product `default-members` and
is consumed through dev-dependencies and test targets. Rich work-meter storage
is enabled by an explicit `conformance-metrics` feature in VM-free and signed
structural-test builds. Product and uninstrumented timing builds retain the same
emission boundaries but compile the collector to a no-op. The feature closure
and product-default exclusion are checked by the existing layering gates.

TOML supplies metadata, budgets, and bindings; it does not describe executable
syscall scenarios. Scenario code remains typed Rust until repeated real
contracts justify a separate language.

### Contract descriptor

The initial system uses a versioned Rust descriptor rather than a new scenario
language:

```text
ConformanceContract
  schema_version
  id
  title
  guest_surfaces
  semantic_authority
  fixture
  scale_points
  layer_bindings
  structural_budgets
  runtime_ratio_policy
  rationale
```

Contract IDs are stable and unique. A rename is a reviewed migration, not a
delete-and-add operation. `guest_surfaces` assigns the contract to syscall,
subsystem, acceleration, backend, or lifecycle ownership used by the ratchets.

`semantic_authority` names the committed Docker oracle, Linux documentation, or
other durable Linux evidence. `rationale` explains why each work budget follows
from the intended architecture.

Layer bindings are deliberately hand-written at first:

- the VM-free binding builds and runs `carrick-kernel-example` `Step` sequences;
- the embed binding selects a guest probe or workload and runs it in process;
- the Docker binding identifies the exact oracle fixture; and
- an optional ecosystem binding names larger suites exercising the family.

The bindings prove different claims while reporting against one contract. This
avoids falsely treating a scripted dispatcher trace and a guest program as the
same execution.

### Contract observation

Every runner emits one typed observation:

```text
ContractObservation
  schema_version
  contract_id
  execution_layer
  implementation_revision
  fixture_identity
  semantic_assertions
  work_snapshot
  timing_distribution
  completeness
```

`timing_distribution` is absent for VM-free structural runs and present only for
approved uninstrumented measurements. `completeness` records unknown counters,
dropped events, unsupported dimensions, and fixture problems. Anything other
than complete is a failing measurement.

The observation is serializable for receipts, but the authoritative gate is the
typed in-process evaluation. JSON output does not become a mutable baseline that
can excuse failures.

### Work meter

The work meter is scoped to the tested kernel graph, container, or execution
generation. It is never a process-global counter whose deltas can be polluted by
parallel tests. A runner obtains a before/after snapshot for its exact scope.

The initial counter taxonomy is intentionally small:

- kernel dispatches and redispatches;
- continuation enrollments, parks, wake publications, resumes, and cancellations;
- guest-memory bytes read, written, copied, zeroed, and materialized;
- VFS/backend operations and directory entries visited;
- host syscall or backend calls;
- page-table edits, invalidations, and backing allocations; and
- task/vCPU admissions, releases, and migrations.

New counter names require documentation, stable units, a scope definition, and
tests proving isolation. Unknown names, overflow, event loss, or unscoped data
fail closed.

VM-free execution may use rich test instrumentation because its result is a
structural proof, not a timing result. Embed structural validation uses narrowly
scoped runtime counters or existing invariant observers. Release timing is a
separate uninstrumented pass. The two passes share source, contract ID, and
fixture identity, but their artifacts and claims remain explicit.

### Budget forms

Contracts support three budget forms:

- exact: `guest_memory_copy_bytes == 0`;
- upper bound: `host_backend_calls <= 2`; and
- scaling: `queue_visits(n) <= base + coefficient * n`.

Scaling contracts execute multiple deterministic sizes. A fixed ceiling is not
sufficient where it could hide quadratic behavior at small fixtures. A budget
failure reports the formula, scale point, expected bound, actual value, and the
smallest failing point.

Generated schedules may be added after the initial contract families establish
a common vocabulary. Every generated failure records its seed and shrinks to a
durable deterministic regression.

### Failure model

The gate reports typed failures:

- `SemanticMismatch`;
- `WorkBudgetExceeded`;
- `ScalingViolation`;
- `IncompleteMeasurement`;
- `FixtureMismatch`;
- `RuntimeRatioExceeded`; and
- `UnsupportedLayer`.

Missing counters, dropped events, absent probes, missing oracle identity, and
unrecognized work categories are measurement failures, not skips.
`UnsupportedLayer` is allowed only when the contract descriptor explicitly
excludes that layer and explains why.

## Evidence flow

The same contract identity flows upward:

```text
VM-free semantic + structural contract
              |
              v
signed embed semantic + structural binding
              |
              v
pinned Docker differential and timing distribution
              |
              v
CLI/probe/ecosystem acceptance
```

Routine development begins with cached Linux authority and VM-free/embed
reducers. Docker execution is a deliberate serial oracle or performance phase;
Carrick and Docker never run concurrently. Final promotion preserves Carrick's
existing order on one exact signed artifact:

```text
just conformance-probes
just conformance smoke
just conformance
```

Any red rung blocks promotion. Full ecosystem runs remain necessary because
composition can expose costs that no isolated contract models.

## Project-wide engineering policy

### Scope

The policy applies to every change that can alter guest-visible behavior or its
operational cost, regardless of crate. This includes syscall dispatch, VFS,
memory, scheduling, signals, networking, process lifecycle, image/startup
behavior, VMM projections, acceleration paths, and host backend implementations.

Pure documentation, mechanical moves, generated inventory rebinding, and
provably host-only changes may be exempted with a narrow rationale. An exemption
may not claim that performance is out of scope for a guest-visible change.

### Normative documentation

Implementation adds three mutually consistent surfaces:

1. a concise load-bearing rule in root `AGENTS.md`;
2. `docs/conformance-contracts.md`, the full engineering guide; and
3. `.agents/skills/carrick-conformance-contract/SKILL.md`, mandatory for agents
   planning or implementing guest-visible work.

The root rule states that guest-visible correctness includes Linux semantics and
non-pathological complexity; agents must identify or add a contract red-first,
prove it in the cheapest capable layer, and complete the applicable signed
gates. Timeout increases, retries, lower concurrency, symptom serialization,
and weakened budgets are not accepted closure.

The repository skill requires an agent to:

1. classify the affected guest contract;
2. locate existing semantic and cost coverage;
3. choose the cheapest capable execution layer;
4. define semantic and structural red evidence before implementation;
5. record any unsupported layer honestly;
6. run the applicable contract and signed promotion gates; and
7. leave exact evidence and non-completion conditions.

### Mechanical enforcement

The repository adds a validator under `scripts/` and calls it from
`just lint-domains`. Its unit tests run with the existing script-test suite.

The validator rejects:

- malformed schemas or duplicate contract IDs;
- unknown guest surfaces, layers, counters, or budget forms;
- missing semantic authority, rationale, or required bindings;
- a scaling budget with insufficient scale points;
- automatically weakened or silently removed budgets;
- new guest-facing syscall handlers, acceleration paths, backend operations, or
  public guest features without a contract-family assignment; and
- registry/binding inventory drift.

CI additionally runs a base-aware changed-path ratchet. A change to a known
guest-visible surface must also change an applicable contract/binding/test, or
carry a narrow reviewed exemption. The classifier is conservative and explicit:
its surface map is checked in and reviewed, and unclassified new paths fail
closed rather than silently becoming host-only.

Exceptional changes use an append-only receipt under
`docs/conformance-exemptions/`. A receipt names the base and head revisions,
classified paths, responsible contract families, and why no semantic or work
expectation changed. The validator rejects broad globs, missing revisions,
unowned paths, duplicate receipts, and rationales that merely declare
performance out of scope. Pure rename detection may be automatic when Git
proves byte identity; all other exemptions remain explicit review artifacts.

The ratchet cannot prove that a test is adequate. It prevents omission; the
runtime contract proves substance. Enforcement scripts receive red-first unit
tests for missing coverage, malformed exemptions, weakened budgets, and
unclassified surfaces.

A change template records:

- contract IDs;
- semantic red evidence;
- structural red evidence;
- final VM-free results;
- signed embed and Docker results where applicable;
- exact artifact provenance for final promotion; and
- deferred higher-layer gates and why they remain open.

## First vertical slice: futex contention

Futex contention proves the architecture by unifying existing VM-free tests,
signed shared-buffer/futex coverage, and guest performance probes. It exercises
blocking, wake selection, continuation ownership, scheduler interaction,
scaling, and a meaningful Docker comparison without touching the active
network/epoll work in the original checkout.

The contract uses deterministic scale points 1, 8, 32, and 128 and proves:

- exact wake cardinality and Linux return values;
- no lost wake or polling-based progress;
- one continuation enrollment and park per blocking episode;
- work proportional to affected waiters rather than historical queue size;
- no repeated redispatch while parked;
- bounded allocations and queue visits per wait/wake;
- signed guest preservation of the semantics; and
- accepted guest ping-pong and contention ratios against pinned same-image
  Docker.

The budget coefficients are justified from the queue and continuation design,
not chosen as the current measurement plus headroom.

The existing tests remain in place until the new contract has demonstrated
equivalent or stronger failure detection. Red-first qualification must show
semantic and structural failures independently, using a known-bad revision or a
deliberate test-only fault where historical execution is impractical.

## Rollout

### Phase 1: standard and framework

- add the root rule, engineering guide, and repository skill;
- define the descriptor, observation, typed failures, and counter taxonomy;
- add scoped work-meter infrastructure;
- add the registry validator, changed-surface ratchet, and their tests; and
- emit observations without deleting existing gates.

### Phase 2: futex vertical slice

- register the futex-contention contract;
- bind the VM-free tests, signed embed fixture, Docker fixture, and existing
  latency probe;
- prove red-first semantic and structural detection;
- add the VM-free contract to `just test-kernel`; and
- add the signed binding to the existing embed/conformance gate.

### Phase 3: high-value families

Migrate contract families in this order:

1. fork, wait, and process retirement;
2. mmap, materialization, and COW;
3. epoll and readiness;
4. filesystem traversal and copy amplification; and
5. sockets and buffered I/O.

Existing tests are linked or adapted rather than rewritten merely for uniformity.
Property-generated schedules and shrinking begin only after these families show
which scenario vocabulary is genuinely shared.

## Verification and acceptance

Framework implementation requires:

- unit tests for descriptor parsing, budget evaluation, observations, counter
  isolation, overflow/drop handling, validator behavior, and diff classification;
- red-first tests for every enforcement failure mode;
- `just test-kernel` for the VM-free contract;
- `just test` and `just ci` for host-wide integration;
- signed embed execution through the shipped signing path; and
- the required signed promotion ladder on the final integrated artifact.

Timing acceptance uses release builds, pinned same-image Docker, serialized
Carrick and Docker phases, distribution statistics rather than a single sample,
and contemporaneous provenance. Instrumented runs are never timing evidence.

Completion of Phase 1 or the futex vertical slice does not imply whole-project
conformance or the <=2x ecosystem goal. Claims remain contract- and
artifact-specific until the full frozen acceptance denominator passes.

## Non-goals

- Replacing the Docker oracle with Carrick-authored expectations.
- Generating arbitrary guest programs from VM-free scripts in the first version.
- Treating the contract registry as a baseline-excuse mechanism.
- Making public hosted CI claim guest execution.
- Adding retries, longer timeouts, lower concurrency, or serialization to hide
  load-coupled failures.
- Deleting existing tests before equivalent contract evidence is demonstrated.

## Risks and mitigations

**Instrumentation perturbs the measured path.** Structural and timing passes are
separate, and only uninstrumented release runs supply timing evidence.

**Counters become implementation trivia.** The taxonomy admits only stable work
units with architectural rationale; contracts prefer scaling laws over internal
line-by-line events.

**The changed-path ratchet creates false positives.** Exemptions exist for
provably non-behavioral changes, but are narrow, reviewed, and machine-validated.

**Agents satisfy the form without the substance.** The skill forces red-first
evidence, while typed runtime contracts and signed promotion gates independently
test the claims.

**The framework becomes a project of its own.** The first deliverable is one
futex vertical slice using existing tests and probes. A scenario DSL and broad
generation are explicitly deferred until real contracts justify them.
