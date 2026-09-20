# Contract-driven conformance investigation

Date: 2026-09-20
Status: proposed design; awaiting written-spec review

## Purpose and agreed scope

Reduce the time between an ecosystem failure and a precise failing conformance
contract. The primary bottleneck is carrying reasoning between execution layers
and reducing failures; fix-validation turnaround is second. Agents must stop
depending on repeated human reminders to use contracts and non-VMM backends.

Conformance results are the default investigation trigger; manual selection is
also supported. Robots investigate autonomously, implement fixtures, measurement
support and missing non-VMM harness capabilities, and produce a failing contract,
an evidence-backed diagnosis and a proposed correction with validation steps.
Production corrections require subsequent review. Investigations use coordinated
execution and park when configured experiment or resource budgets are exhausted.

The first release inventories every syscall and completes one real investigation
end to end. It does not fill every coverage gap. Historical inotify, epoll and
fork work informs requirements; replaying those campaigns is not the acceptance
objective. No implementation is authorized by this design document.

## Existing foundation

Extend the existing system rather than create a competing contract framework:

- `carrick-conformance-contract` supplies typed descriptors, observations,
  evaluation and failure classes.
- `conformance-contracts/contracts/` currently contains eleven descriptors;
  `surfaces.toml` associates source paths with contracts.
- `carrick-kernel-example` scripts the public kernel API without a VMM, using
  real continuation enrollment and completion rather than polling.
- `carrick-embed` and existing Docker/probe/ecosystem runners provide additional
  execution evidence.
- `check-contract-change.py` checks changed-path associations. Such associations
  and edited test files are not execution receipts or proof of claim coverage.

The normative correctness definition remains Linux semantics plus bounded work
and applicable runtime ratios in `docs/conformance-contracts.md`. Existing
contracts and observations must migrate explicitly if their schemas change.

## 1. Coverage by claim and capability

Generate the syscall denominator from the authoritative ABI and architecture
tables. Preserve architecture, aliases and declared support level; account for
every declared entry without treating an alias as a new independent behavior.
Supported and partially supported syscalls need explicit claims about implemented
behavior and known gaps. Deferred calls need claims for their declared refusal
behavior; these do not count as implemented Linux semantics.

Maintain claims for operation semantics, error and memory effects, blocking and
wakeup behavior, cross-syscall lifecycle interactions, and structural work or
scaling. One contract can cover several syscalls, and one syscall can require
many contracts. Include kernel/runtime invariants not attributable to one syscall.

Each claim has a stable identity, Linux authority, fixture requirements, related
contracts and ecosystem rows, required capabilities, applicable layers, and
budgets with architectural rationales. Distinguish declared coverage, implemented
binding, executed evidence and demonstrated violation detection. Report unknown
and unenumerated behavior explicitly: a complete syscall inventory is not a
claim that every semantic branch has been enumerated or proven.

Backend capabilities describe what a binding can actually exercise. Classify
each investigation claim as:

1. Provable with an existing non-VMM backend capability.
2. Provable without a VMM, but requiring a harness extension.
3. Requiring real guest execution, runtime integration or VMM behavior.

Classification includes the specific capability and rationale. An unsupported
harness operation cannot silently be classified as intrinsically VMM-dependent.
Retain lower-layer assertions when only part of a claim requires a higher layer.
Zero work in a backend where the relevant mechanism is absent is not proof of
that mechanism's budget. Applicability and measurement completeness are separate.

Robot-generated claims require semantic authority, active-fixture checks and
evidence of violation detection. A relevant known-bad revision supplies red
evidence for a real regression. Controlled faults can qualify an assertion or
meter, but cannot substitute for reproducing the selected ecosystem defect.
Budgets are never inferred from current observed costs alone or widened by
automation to make a run pass.

## 2. Enforced investigation flow

Use a durable investigation record and validated transitions:

`queued -> classified -> reducing -> diagnosing -> review-ready`

Any active stage can become `parked`; resumption returns to the recorded stage
after checking evidence validity. Additional experiments may return diagnosis
to reduction without discarding earlier evidence. Infrastructure failures remain
distinct from reproduced guest failures.

The record contains the selected run and failure, source/artifact/fixture/oracle
identities, claims, capability classification, competing hypotheses, experiments,
observations, reductions, remaining gaps, resource usage and next action.
Experiment plans state the question, discriminating outcomes, required layer
and resources before execution. Results distinguish observations from inference.

Transition prerequisites:

- Classification requires the contract lookup and non-VMM capability decision.
- Reduction uses the cheapest capable layer and extends the harness where
  appropriate. A reduction records which semantic or structural mechanism it
  preserves and the evidence connecting it to the original failure.
- Diagnosis requires meaningful red evidence, verified fixture activity,
  trustworthy measurement and experiments distinguishing plausible alternatives.
- Review-ready requires a replayable failing contract, Linux authority,
  evidence-backed diagnosis, proposed correction, affected invariants, validation
  plan and explicitly open higher-layer gates.

The engine can validate fields, identities, executed bindings and evidence
dependencies. It cannot mechanically guarantee that an agent's causal argument
is sound; the review package retains that reasoning for human assessment.

Agents may implement test fixtures, observation support and missing non-VMM
harness capabilities. These changes must use real public kernel semantics,
preserve layering and avoid substitutes that encode the desired answer. Any
necessary production-path instrumentation is separately identified, scoped and
validated for semantic neutrality and perturbation. Changes to production
semantics, ownership, algorithms or policy remain proposed corrections.

## 3. Runner and execution coordination

Provide one contract-oriented entry point for planning and running named claims
or contracts through registered bindings. Reuse repository recipes and existing
typed observations; add an evidence envelope for exact identities, capabilities,
commands, logs and investigation links. Semantic, structural and timing evidence
remain distinct. Missing bindings and incomplete measurements fail explicitly.

Use a host-wide coordinator shared across participating checkouts. It grants
resource leases for builds, signed guest runs, tracing, timing and Docker phases.
Carrick and Docker phases never overlap. Timing measurements require a quiet
exclusive window; heavy builds and other experiments are excluded from it.
Source analysis and lightweight preparation may continue while experiments queue.
Do not replace an artifact while an active run uses it; preserve per-run artifacts.

Lease ownership includes host, process identity, investigation, run ID and
resource class. Crash recovery reconciles actual processes and scoped cleanup
before releasing a lease; elapsed time alone does not establish resource safety.
Existing runner entry points must participate for coordination to be reliable.
Detected unmanaged competing work invalidates measurement admission or its
quiet-host claim; a cooperative lock cannot promise control of arbitrary tools.

Evidence reuse is conservative: require matching declared source/dependency,
fixture, instrumentation, backend, artifact and oracle identities. If dependency
scope is unknown, invalidate on source change. Discovery observations never
become acceptance evidence merely through reuse. Signed acceptance still uses
one exact artifact through probes, smoke and full promotion with provenance and
scoped cleanup.

## 4. Intake, budgets and coverage expansion

Ingest machine-readable conformance results and retain the declared denominator,
raw evidence and provenance gaps. Rank semantic failures and severe pathologies;
group candidates only when evidence supports a shared mechanism. Suite names
and syscall names alone are not causal classifications. Manual selection enters
the same queue and follows the same requirements.

Each campaign declares finite experiment, elapsed execution and resource budgets.
Do not start unattended execution without them. Scheduling and limits are
configuration, not conformance policy: reaching a campaign limit parks an
investigation and never converts its failure into a skip or pass. Check budgets
at experiment boundaries, and use bounded runner cleanup for an in-flight limit.

Parking preserves evidence, tested and remaining hypotheses, the obstruction,
consumed budget and a concrete resumption condition. It releases resources after
verified cleanup and advances the queue. Request human input when an architectural
decision or changed authorization is needed. Avoid repeating identical experiments
without an explicit evidentiary purpose; retries are not closure.

After the first end-to-end workflow works, robots expand coverage using the
inventory: current failure clusters first, then uncovered claims and interactions.
Every generated contract passes fixture, authority and violation-detection checks.
Count declared, executable and evidenced coverage separately. Unresolved gaps stay
visible rather than becoming fabricated green coverage.

## Delivery sequence

1. Extend the claim/capability model and generate the complete syscall inventory.
   Import existing contracts with honest applicability and evidence states.
2. Add durable investigations, transition validation and contract-oriented runner
   adapters; enforce the non-VMM decision and review-package prerequisites.
3. Add coordinated execution, conformance intake, campaign budgets and parking.
4. Complete one current real failure through the integrated workflow and review
   its package. Use observed friction to refine the workflow before scaling it.
5. Expand robot-driven contract coverage and tighten change enforcement around
   actual claim evidence rather than file associations alone.

The implementation plan will specify executable interfaces, schema migration,
module ownership and tests within these boundaries after written-spec approval.

## First-release acceptance

- The generated inventory accounts for every authoritative syscall entry and
  exposes missing claims and bindings without overstating coverage.
- A selected real conformance failure reaches a failing contract, diagnosis and
  proposed correction through the enforced workflow. It performs the non-VMM
  capability decision and uses or extends that backend wherever capable.
- Missing evidence, inactive fixtures, inapplicable zero counters, stale identities
  and unsupported layers cannot advance an investigation to review-ready.
- An interrupted investigation resumes from durable state without redoing valid
  completed experiments. A budget-exhausted investigation parks and releases
  resources safely while another candidate can advance.
- Coordinator tests demonstrate exclusion of conflicting phases, protection of
  active artifacts and crash recovery without unsafe lease release.
- Record time to first meaningful red contract, active experiment time, queue
  wait, experiment count, repeated work and human corrective prompts. The pilot
  must complete without reminders to perform the contract/backend decision.
  Establish these measurements before claiming a numerical speedup.
- No production correction is applied by the autonomous investigation. Open
  signed and ecosystem gates remain explicit; investigation completion is not
  conformance closure.

## Risks and safeguards

False confidence from a complete-looking inventory is addressed by claim-level
states and explicit unknowns. A mock-like harness can hide the defect; use the
real kernel API and declare unsupported capabilities. Fault injection can test
the wrong instrument; keep real-defect red evidence distinct. Overly elaborate
orchestration can delay useful reduction; the first release must complete one
real case before broad generation. Agent judgment can remain wrong despite
valid schemas; retain hypotheses, causal evidence and the review boundary.
