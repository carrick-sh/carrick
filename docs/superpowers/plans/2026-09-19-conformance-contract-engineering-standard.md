# Conformance Contract Engineering Standard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Linux semantics and non-pathological operational complexity one enforceable conformance obligation for every Carrick change that can affect guest-visible behavior, then prove the system with a futex-contention vertical slice.

**Architecture:** A dev-only `carrick-conformance-contract` crate parses reviewed TOML descriptors, evaluates typed semantic/work/timing observations, and emits fail-closed results. `carrick-observability` supplies execution-scoped counters behind `conformance-metrics`; VM-free and signed embed bindings report against the same stable contract ID, while repository policy, a mandatory agent skill, registry validation, and a base-aware changed-surface ratchet prevent guest-visible changes from bypassing the workflow.

**Tech Stack:** Rust 2024, serde/toml/thiserror, Carrick's VM-free `carrick-kernel-example`, signed `carrick-embed`, Python 3 `unittest` and `tomllib` for diff ratchets, `just`, GitHub Actions, Markdown/TOML policy artifacts.

**Spec:** `docs/superpowers/specs/2026-09-19-conformance-contract-engineering-standard-design.md`

## Global Constraints

- The policy applies to every change that can alter guest-visible behavior or operational cost, regardless of crate.
- Linux defines observable semantics; Carrick's intended architecture defines structural work invariants.
- A semantic pass cannot excuse a structural-budget or runtime-ratio failure.
- VM-free structural counts are the primary inner-loop signal; instrumented timing is never performance evidence.
- Signed timing uses an uninstrumented release artifact and pinned same-image Docker in serialized phases.
- Unknown counters, dropped observations, missing bindings, missing oracle identity, and unsupported unapproved layers fail closed.
- Budgets support exact, upper-bound, and affine scaling forms and cannot be automatically weakened.
- Preserve existing tests until the futex contract demonstrates equivalent or stronger failure detection.
- Preserve the existing promotion order: `just conformance-probes` -> `just conformance smoke` -> `just conformance`, on one final signed artifact.
- Never run Carrick and Docker concurrently; stamp `CARRICK_RUN_ID` and use scoped cleanup.
- Do not use retries, longer timeouts, reduced concurrency, polling, or symptom serialization as closure.
- Keep `carrick-conformance-contract` outside the product default-member closure; `just check-layering` must prove this.
- Preserve unrelated work and do not push.

## Review Focus

- A contract with a syntactically valid but unknown metric or layer must fail validation rather than silently omit the check; Task 2 adds parser tests for both cases.
- Parallel contract runs must never contaminate one another's counters, even when scope IDs are reused after retirement; Task 4 adds concurrent isolation and stale-generation tests.
- A base-aware diff containing a renamed byte-identical file should pass without an exemption, while a modified guest-visible file must require contract evidence; Task 5 tests both cases.
- An instrumented embed observation must never populate timing evidence, and an uninstrumented timing observation must not claim structural completeness; Task 3 tests both illegal combinations.
- Futex work must scale with affected waiters rather than historical queue population, including zero-wake and partial-wake cases; Task 6 tests scale points 1, 8, 32, and 128 plus a larger unrelated population.

---

### Task 1: Install the normative project policy and mandatory agent workflow

Before editing the repository skill, read and follow `superpowers:writing-skills`; its verification requirements apply in addition to the steps below.

**Files:**
- Create: `docs/conformance-contracts.md`
- Create: `.agents/skills/carrick-conformance-contract/SKILL.md`
- Create: `scripts/tests/test_conformance_contract_policy.py`
- Modify: `AGENTS.md` in the `Engineering standards` section
- Modify: `docs/conformance-testing.md` after `Kernel semantics suite`
- Modify: `justfile` in `lint-domains`

**Interfaces:**
- Consumes: the approved design spec and existing commands `just test-kernel`, `just test-embed`, `just conformance-probes`, `just conformance smoke`, and `just conformance`.
- Produces: the normative phrase `guest-visible correctness includes Linux semantics and non-pathological operational complexity`; a mandatory skill path `.agents/skills/carrick-conformance-contract/SKILL.md`; and policy-link tests executed by `just lint-domains`.

- [ ] **Step 1: Write the failing policy-link tests**

Create `scripts/tests/test_conformance_contract_policy.py` with exact assertions that the root rule names the skill, the guide names all failure classes, and the skill contains the mandatory workflow:

```python
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ConformanceContractPolicyTest(unittest.TestCase):
    def test_agents_rule_requires_contract_skill(self):
        text = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        self.assertIn("guest-visible correctness includes Linux semantics", text)
        self.assertIn(".agents/skills/carrick-conformance-contract", text)
        self.assertIn("A semantic pass cannot excuse", text)

    def test_guide_names_every_fail_closed_result(self):
        text = (ROOT / "docs/conformance-contracts.md").read_text(encoding="utf-8")
        for name in (
            "SemanticMismatch",
            "WorkBudgetExceeded",
            "ScalingViolation",
            "IncompleteMeasurement",
            "FixtureMismatch",
            "RuntimeRatioExceeded",
            "UnsupportedLayer",
        ):
            self.assertIn(name, text)

    def test_skill_requires_red_first_and_signed_promotion(self):
        text = (ROOT / ".agents/skills/carrick-conformance-contract/SKILL.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("red-first", text)
        self.assertIn("just conformance-probes", text)
        self.assertIn("just conformance smoke", text)
        self.assertIn("just conformance", text)
        self.assertIn("Do not weaken", text)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the policy test and verify the missing artifacts fail**

Run:

```bash
python3 -m unittest scripts/tests/test_conformance_contract_policy.py
```

Expected: FAIL because `docs/conformance-contracts.md` and `.agents/skills/carrick-conformance-contract/SKILL.md` do not exist and `AGENTS.md` lacks the new mandatory rule.

- [ ] **Step 3: Add the concise root rule**

Add a `Guest-visible conformance contracts` subsection near `The two gates, in order` in `AGENTS.md`. It must say, verbatim where asserted:

```markdown
### Guest-visible conformance contracts

Guest-visible correctness includes Linux semantics and non-pathological operational complexity. Before planning or implementing any change that can affect guest-visible behavior or cost, use [`.agents/skills/carrick-conformance-contract`](.agents/skills/carrick-conformance-contract/SKILL.md), identify the applicable contract, and add one red-first when none exists. Prove semantics and deterministic work budgets in the cheapest capable layer, then complete the applicable signed gates. A semantic pass cannot excuse a structural-budget or runtime-ratio failure. Do not weaken budgets, add retries, increase timeouts, reduce concurrency, poll, or serialize symptoms as closure.
```

- [ ] **Step 4: Write the engineering guide**

Create `docs/conformance-contracts.md` by translating the approved spec into an operator-facing guide with these exact sections: `Definition of correctness`, `Evidence ladder`, `Contract descriptor`, `Work budgets`, `Failure classes`, `Red-first workflow`, `Changing a budget`, `Exemptions`, `Commands`, and `Futex example`. Include the exact typed failure names tested above, the three budget forms, the separate instrumented/untimed and uninstrumented/timed passes, and the existing signed promotion order.

- [ ] **Step 5: Write the repository skill**

Create `.agents/skills/carrick-conformance-contract/SKILL.md` with YAML frontmatter and an imperative checklist:

```markdown
---
name: carrick-conformance-contract
description: Required before planning or implementing any Carrick change that can affect guest-visible Linux behavior or operational cost.
---

# Carrick conformance contract workflow

1. Read `AGENTS.md`, `docs/conformance-contracts.md`, and the applicable controller.
2. Name the guest surface and existing contract ID; if absent, add the contract red-first.
3. State the Linux semantic authority and the Carrick structural invariant.
4. Choose the cheapest capable layer and capture semantic and structural red evidence.
5. Implement the smallest architectural correction; do not weaken a budget, retry, increase a timeout, lower concurrency, poll, or serialize symptoms.
6. Run the VM-free contract, the signed embed binding, and the applicable Docker differential.
7. Promote in order: `just conformance-probes`, `just conformance smoke`, `just conformance`.
8. Record exact evidence, artifact provenance, cleanup, and every uncompleted higher-layer gate.
```

Add explicit stop conditions for incomplete measurement, missing oracle identity, unsupported unregistered layers, and valid completing ratios at or above 10x Docker.

- [ ] **Step 6: Cross-link the guide from conformance documentation**

Add a paragraph to `docs/conformance-testing.md` stating that every guest-visible semantics test must name a contract ID, structural budgets run in `just test-kernel`, and signed/timing claims follow `docs/conformance-contracts.md`.

- [ ] **Step 7: Put the policy test in the gate and verify green**

Add this command near the other named Python unit tests in `just lint-domains`:

```just
python3 -m unittest scripts/tests/test_conformance_contract_policy.py
```

Run:

```bash
python3 -m unittest scripts/tests/test_conformance_contract_policy.py
git diff --check
```

Expected: three tests PASS and no whitespace errors.

- [ ] **Step 8: Commit the normative policy**

```bash
git add AGENTS.md docs/conformance-contracts.md docs/conformance-testing.md .agents/skills/carrick-conformance-contract/SKILL.md scripts/tests/test_conformance_contract_policy.py justfile
git commit -m "docs: require conformance contracts for guest-visible changes"
```

### Task 2: Build the contract descriptor and registry model

**Files:**
- Create: `crates/carrick-conformance-contract/Cargo.toml`
- Create: `crates/carrick-conformance-contract/src/lib.rs`
- Create: `crates/carrick-conformance-contract/src/model.rs`
- Create: `crates/carrick-conformance-contract/src/registry.rs`
- Create: `crates/carrick-conformance-contract/tests/registry.rs`
- Create: `conformance-contracts/contracts/futex-contention.toml`
- Create: `conformance-contracts/surfaces.toml`
- Modify: `Cargo.toml` workspace dependencies only if needed; do not add the crate to `default-members`

**Interfaces:**
- Consumes: `serde::Deserialize`, `toml::from_str`, and the counter names defined provisionally by `WorkMetric` in this task and moved to `carrick-observability` in Task 4.
- Produces: `ContractRegistry::load(root: &Path) -> Result<Self, RegistryError>`, `ContractRegistry::get(&self, id: &ContractId) -> Option<&ConformanceContract>`, `ContractRegistry::require(&self, id: &str) -> Result<&ConformanceContract, RegistryError>`, `ContractId`, `ExecutionLayer`, `WorkMetric`, `Budget`, `LayerBindings`, and `RuntimeRatioPolicy`.

- [ ] **Step 1: Write red parser and registry tests**

Create tests that parse a complete futex descriptor and reject duplicate IDs, unknown layers, unknown metrics, missing rationale, and scaling budgets with fewer than three scale points. The central positive assertion is:

```rust
#[test]
fn futex_contract_has_structural_and_runtime_authority() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry
        .get(&ContractId::new("kernel.futex.contention").expect("id"))
        .expect("futex contract");
    assert_eq!(contract.scale_points, vec![1, 8, 32, 128]);
    assert!(contract.bindings.vm_free.is_some());
    assert!(contract.bindings.embed.is_some());
    assert!(contract.bindings.docker.is_some());
    assert!(contract.runtime_ratio.is_some());
}
```

For negative fixtures, write temporary `contracts/*.toml` files and assert precise `RegistryError` variants rather than string matching.

- [ ] **Step 2: Run the registry test and verify the crate is absent**

```bash
RUSTC_WRAPPER= cargo test -p carrick-conformance-contract --test registry
```

Expected: FAIL with `package ID specification carrick-conformance-contract did not match any packages`.

- [ ] **Step 3: Create the dev-only crate and typed descriptor**

Define these public types in `model.rs`:

```rust
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ContractId(String);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionLayer { VmFree, EmbedStructural, EmbedTiming, Docker, Ecosystem }

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkMetric {
    KernelDispatches,
    KernelRedispatches,
    ContinuationEnrollments,
    ContinuationParks,
    WakePublications,
    ContinuationResumes,
    GuestMemoryReadBytes,
    GuestMemoryWriteBytes,
    GuestMemoryCopyBytes,
    GuestMemoryZeroBytes,
    BackingMaterializedBytes,
    VfsBackendOperations,
    DirectoryEntriesVisited,
    HostBackendCalls,
    PageTableEdits,
    PageTableInvalidations,
    BackingAllocations,
    TaskAdmissions,
    VcpuAdmissions,
    VcpuReleases,
    VcpuMigrations,
    FutexQueueVisits,
    FutexWaitersWoken,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Budget {
    Exact { metric: WorkMetric, value: u64 },
    UpperBound { metric: WorkMetric, maximum: u64 },
    Affine { metric: WorkMetric, base: u64, per_unit: u64 },
}
```

`ContractId::new` accepts lowercase ASCII segments separated by `.` or `-`, rejects empty segments, and returns `ModelError::InvalidContractId` otherwise. `ConformanceContract` includes every field from the spec and uses `deny_unknown_fields` on every TOML-facing struct.

- [ ] **Step 4: Implement fail-closed registry loading**

`ContractRegistry::load` sorts `conformance-contracts/contracts/*.toml`, rejects non-TOML files, parses one descriptor per file, detects duplicate IDs before insertion, validates bindings/rationale/scale points, loads `surfaces.toml`, and verifies every referenced contract family exists.

Use explicit variants:

```rust
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("cannot read contract registry path {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("invalid contract TOML {path}: {source}")]
    Toml { path: PathBuf, source: toml::de::Error },
    #[error("duplicate contract id {0}")]
    Duplicate(ContractId),
    #[error("contract {id} has no rationale for budget {index}")]
    MissingBudgetRationale { id: ContractId, index: usize },
    #[error("contract {id} scaling budget requires at least three scale points")]
    InsufficientScalePoints { id: ContractId },
    #[error("surface {surface} references unknown contract family {contract}")]
    UnknownSurfaceContract { surface: String, contract: ContractId },
}
```

- [ ] **Step 5: Add the initial futex descriptor and source map**

`conformance-contracts/contracts/futex-contention.toml` must use ID `kernel.futex.contention`, scale points `[1, 8, 32, 128]`, cite `man 2 futex` plus the committed `futexpingpong`/`futexwakeexact` Docker oracle entries, and name bindings:

```toml
[bindings]
vm_free = "carrick-kernel-example::futex_contention_contract"
embed = "carrick-embed::futex_contention_contract"
docker = "probe:futexpingpong"
ecosystem = ["go:sync", "cpython:concurrent_futures"]

[[structural_budgets]]
kind = "affine"
metric = "continuation_enrollments"
base = 0
per_unit = 1
rationale = "Each blocking waiter enrolls exactly once before parking."

[[structural_budgets]]
kind = "affine"
metric = "futex_queue_visits"
base = 1
per_unit = 1
rationale = "Wake visits only the queue head and the affected waiter set."

[runtime_ratio]
maximum = 2.0
statistic = "p50"
minimum_samples = 20
```

Map `crates/carrick-kernel/src/dispatch/futex.rs`, `crates/carrick-kernel/src/kernel/continuation.rs`, `crates/carrick-thread/src/platform_futex.rs`, and the futex-related probe/test paths to this family in `surfaces.toml`.

- [ ] **Step 6: Run registry and workspace-boundary tests**

```bash
RUSTC_WRAPPER= cargo test -p carrick-conformance-contract --test registry
RUSTC_WRAPPER= cargo metadata --no-deps --format-version 1 >/tmp/carrick-contract-metadata.json
just check-layering
```

Expected: registry tests PASS; `carrick-conformance-contract` is a workspace member but absent from `workspace_default_members`; layering passes.

- [ ] **Step 7: Commit the contract model**

```bash
git add Cargo.toml Cargo.lock crates/carrick-conformance-contract conformance-contracts
git commit -m "test(conformance): add typed contract registry"
```

### Task 3: Evaluate observations and budgets fail closed

**Files:**
- Create: `crates/carrick-conformance-contract/src/observation.rs`
- Create: `crates/carrick-conformance-contract/src/evaluate.rs`
- Create: `crates/carrick-conformance-contract/tests/evaluate.rs`
- Modify: `crates/carrick-conformance-contract/src/lib.rs`

**Interfaces:**
- Consumes: `ConformanceContract`, `ExecutionLayer`, `WorkMetric`, and `Budget` from Task 2.
- Produces: `ContractObservation`, `ContractObservation::work_value(metric: WorkMetric) -> Option<u64>`, `WorkSnapshot`, `WorkSnapshot::get(metric: WorkMetric) -> Option<u64>`, `TimingDistribution::new(samples: Vec<f64>) -> Result<Self, ObservationError>`, `Completeness`, `evaluate(contract: &ConformanceContract, observations: &[ContractObservation]) -> Result<ContractPass, ContractFailure>`, and typed failures matching the approved spec.

- [ ] **Step 1: Write failing evaluation tests**

Cover exact success/failure, upper-bound failure, affine failure at the smallest scale point, missing metric, dropped observation, fixture mismatch, semantic mismatch, timing ratio failure, instrumented timing rejection, and uninstrumented structural-completeness rejection. Include:

```rust
#[test]
fn instrumented_observation_cannot_supply_timing_evidence() {
    let mut observation = observation(ExecutionLayer::EmbedStructural, 8);
    observation.timing = Some(TimingDistribution::new(vec![3.0; 20]).expect("timing"));
    assert!(matches!(
        observation.validate(),
        Err(ContractFailure::IncompleteMeasurement { reason, .. })
            if reason.contains("instrumented layer cannot supply timing")
    ));
}

#[test]
fn affine_failure_reports_smallest_scale_point() {
    let contract = futex_contract();
    let observations = [observation_with_visits(1, 2), observation_with_visits(8, 12)];
    assert!(matches!(
        evaluate(&contract, &observations),
        Err(ContractFailure::ScalingViolation { scale: 8, actual: 12, maximum: 9, .. })
    ));
}
```

- [ ] **Step 2: Run the evaluator tests and verify missing APIs fail**

```bash
RUSTC_WRAPPER= cargo test -p carrick-conformance-contract --test evaluate
```

Expected: compile failure because `observation` and `evaluate` modules do not exist.

- [ ] **Step 3: Implement observations with explicit completeness**

Define:

```rust
pub struct ContractObservation {
    pub contract_id: ContractId,
    pub layer: ExecutionLayer,
    pub implementation_revision: String,
    pub fixture_identity: String,
    pub scale: u64,
    pub semantic_assertions: Vec<SemanticAssertion>,
    pub work: Option<WorkSnapshot>,
    pub timing: Option<TimingDistribution>,
    pub completeness: Completeness,
}

pub struct WorkSnapshot {
    values: BTreeMap<WorkMetric, u64>,
    dropped_events: u64,
    unknown_metrics: Vec<String>,
}

pub enum Completeness { Complete, Incomplete { reasons: Vec<String> } }
```

Constructors reject empty revision/fixture identities, non-finite or negative timing samples, fewer samples than the contract requires, duplicate metric insertion, and arithmetic overflow.

- [ ] **Step 4: Implement typed evaluation failures**

Use the exact variants:

```rust
pub enum ContractFailure {
    SemanticMismatch { contract: ContractId, assertion: String },
    WorkBudgetExceeded { contract: ContractId, metric: WorkMetric, actual: u64, maximum: u64 },
    ScalingViolation { contract: ContractId, metric: WorkMetric, scale: u64, actual: u64, maximum: u64 },
    IncompleteMeasurement { contract: ContractId, reason: String },
    FixtureMismatch { contract: ContractId, expected: String, actual: String },
    RuntimeRatioExceeded { contract: ContractId, actual: f64, maximum: f64 },
    UnsupportedLayer { contract: ContractId, layer: ExecutionLayer },
}
```

Evaluation validates every observation before comparing it, requires every metric named by a budget, uses checked arithmetic for `base + per_unit * scale`, reports the first/smallest failing scale deterministically, and never derives missing work from zero.

- [ ] **Step 5: Run focused and crate-wide tests**

```bash
RUSTC_WRAPPER= cargo test -p carrick-conformance-contract
RUSTC_WRAPPER= cargo clippy -p carrick-conformance-contract --all-targets -- -D warnings
```

Expected: all tests PASS and no warnings.

- [ ] **Step 6: Commit the evaluator**

```bash
git add crates/carrick-conformance-contract
git commit -m "test(conformance): evaluate semantic and work budgets"
```

### Task 4: Add execution-scoped work meters without entering timing builds

**Files:**
- Create: `crates/carrick-observability/src/work_meter.rs`
- Create: `crates/carrick-observability/tests/work_meter.rs`
- Modify: `crates/carrick-observability/src/lib.rs`
- Modify: `crates/carrick-observability/Cargo.toml`
- Modify: `crates/carrick-conformance-contract/Cargo.toml`
- Modify: `crates/carrick-conformance-contract/src/model.rs`

**Interfaces:**
- Consumes: no Carrick runtime state; the module is platform-neutral.
- Produces: `WorkScopeId { raw: u64, generation: u64 }`, `WorkMetric`, `WorkSnapshot`, `WorkSnapshot::get(metric: WorkMetric) -> Option<u64>`, `WorkMeter::new_scope() -> WorkScope`, `WorkScope::add(metric, amount)`, `WorkScope::snapshot() -> Result<WorkSnapshot, WorkMeterError>`, and a no-op implementation when `conformance-metrics` is disabled.

- [ ] **Step 1: Write failing scope-isolation tests**

Test exact accumulation, checked overflow, two scopes running concurrently, retired-scope writes, and reuse of a raw ID with a new generation. The concurrency test must use a barrier and two threads, then assert no cross-contamination:

```rust
#[test]
fn concurrent_scopes_do_not_cross_contaminate() {
    let meter = Arc::new(WorkMeter::default());
    let left = meter.new_scope();
    let right = meter.new_scope();
    let barrier = Arc::new(Barrier::new(3));
    // Each worker adds a distinct count to the same metric in its own scope.
    // After both join: left == 10_000 and right == 30_000 exactly.
}
```

The stale-generation test retains a cloned retired handle, creates a new scope after retirement, and requires `WorkMeterError::RetiredScope` from the old handle.

- [ ] **Step 2: Run tests with the feature and verify the module is absent**

```bash
RUSTC_WRAPPER= cargo test -p carrick-observability --features conformance-metrics --test work_meter
```

Expected: compile failure because `work_meter` is not exported.

- [ ] **Step 3: Implement the scoped meter**

Use an `Arc<ScopeState>` owned by `WorkScope`, per-scope `AtomicU64` slots indexed by `WorkMetric`, an `AtomicBool retired`, and a monotonically increasing generation. `add` uses `fetch_update` with `checked_add`; overflow sets an overflow flag and returns `WorkMeterError::Overflow`. `snapshot` fails if overflow or dropped-event flags are nonzero.

Do not use a process-global active scope or thread-local implicit scope. Callers must carry `WorkScope` explicitly through the tested kernel graph/container.

- [ ] **Step 4: Provide the disabled-feature behavior**

With `conformance-metrics` disabled, retain the same method signatures but return `WorkMeterError::Disabled` from `snapshot`; `add` is a no-op. Add a compile test proving default `carrick-observability` has no atomic storage in `WorkScope` by asserting `size_of::<WorkScope>() <= 16`; do not claim timing equivalence from this check.

- [ ] **Step 5: Move `WorkMetric` and `WorkSnapshot` to observability and reuse them**

Remove both provisional duplicates from `carrick-conformance-contract`, depend on `carrick-observability`, and serialize the shared types from that crate. `ContractObservation::work_value` delegates to `WorkSnapshot::get`. Run the Task 2 unknown-metric test again to prove `deny_unknown_fields` and enum parsing remain fail closed.

- [ ] **Step 6: Run feature, default, and layering gates**

```bash
RUSTC_WRAPPER= cargo test -p carrick-observability --features conformance-metrics --test work_meter
RUSTC_WRAPPER= cargo test -p carrick-observability
RUSTC_WRAPPER= cargo test -p carrick-conformance-contract
just check-layering
```

Expected: all tests PASS; the product default closure does not enable `conformance-metrics`.

- [ ] **Step 7: Commit the scoped meter**

```bash
git add Cargo.lock crates/carrick-observability crates/carrick-conformance-contract
git commit -m "test(observability): add scoped conformance work meters"
```

### Task 5: Enforce registry integrity and changed guest surfaces

**Files:**
- Create: `crates/carrick-conformance-contract/src/bin/check-contracts.rs`
- Create: `scripts/conformance/check-contract-change.py`
- Create: `scripts/tests/test_check_contract_change.py`
- Create: `docs/conformance-exemptions/README.md`
- Modify: `justfile` in `lint-domains`
- Modify: `.github/workflows/ci.yml` in hosted `check`

**Interfaces:**
- Consumes: `ContractRegistry::load`, `conformance-contracts/surfaces.toml`, `git diff --name-status -M BASE_SHA...HEAD_SHA`, and optional append-only exemption TOML under `docs/conformance-exemptions/`.
- Produces: `cargo run -p carrick-conformance-contract --bin check-contracts -- --root .`; `check-contract-change.py --root . --base BASE_SHA --head HEAD_SHA`; exit 0 only when every modified guest surface has matching contract evidence, a byte-identical rename, or a valid exemption.

- [ ] **Step 1: Write failing diff-ratchet tests**

In a temporary Git repository, cover:

1. modified guest file without contract/test evidence -> exit 1;
2. modified guest file plus its registered VM-free binding -> exit 0;
3. byte-identical rename detected with `-M` -> exit 0;
4. renamed and edited guest file -> exit 1;
5. new unclassified path under `crates/` -> exit 1;
6. broad exemption glob -> exit 1;
7. exemption missing base/head revisions -> exit 1;
8. exemption saying only `performance out of scope` -> exit 1;
9. exact reviewed exemption for classified paths -> exit 0.

Invoke the script as a subprocess so exit codes and diagnostics are tested. Require diagnostics to name every uncovered path and its nearest known surface owner.

- [ ] **Step 2: Run the ratchet tests and verify the script is missing**

```bash
python3 -m unittest scripts/tests/test_check_contract_change.py
```

Expected: FAIL because `scripts/conformance/check-contract-change.py` does not exist.

- [ ] **Step 3: Add the registry checker binary**

`check-contracts` accepts only `--root PATH`, loads the registry, checks every binding target path/symbol declaration, checks that each surface pattern matches at least one tracked file, and prints `conformance contracts checked: N contracts, M surfaces` on success. Missing paths, vacuous patterns, malformed registry rows, and missing binding targets are distinct errors.

- [ ] **Step 4: Implement the base-aware changed-path ratchet**

Use `argparse`, `subprocess.run(..., check=True)`, `tomllib`, and `pathlib`. Parse `git diff --name-status -M`, classify both old and new names, and consider evidence changed only when a touched path matches the contract's declared binding/test paths. Do not accept any test file as generic evidence.

Exemption receipts use:

```toml
schema = "carrick.conformance-exemption.v1"
base = "1111111111111111111111111111111111111111"
head = "2222222222222222222222222222222222222222"
paths = ["exact/repository/path.rs"]
contracts = ["kernel.futex.contention"]
rationale = "Byte-preserving ownership move; contract behavior and work units are unchanged."
```

Reject globs, directories, abbreviated revisions, paths not in the diff, unknown contract IDs, and rationales shorter than 40 characters.

- [ ] **Step 5: Wire local and CI gates**

Add to `just lint-domains`:

```just
cargo run -p carrick-conformance-contract --bin check-contracts -- --root .
python3 -m unittest scripts/tests/test_check_contract_change.py
```

The base-aware check cannot assume a local base, so add it to `.github/workflows/ci.yml` after checkout with full base availability. For pull requests use `${{ github.event.pull_request.base.sha }}` and `${{ github.sha }}`; for push/manual/nightly run registry validation only. Keep the command in `justfile` as a parameterized recipe:

```just
check-contract-change base head="HEAD":
    python3 scripts/conformance/check-contract-change.py --root . --base {{base}} --head {{head}}
```

- [ ] **Step 6: Run enforcement tests and deliberate red controls**

```bash
RUSTC_WRAPPER= cargo run -p carrick-conformance-contract --bin check-contracts -- --root .
python3 -m unittest scripts/tests/test_check_contract_change.py scripts/tests/test_conformance_contract_policy.py
just check-contract-change HEAD^ HEAD
```

Expected: registry and unit tests PASS. The current documentation-only commit is either outside guest surfaces or covered by its exact policy paths; it must not need a behavioral exemption.

Copy the registry to a temporary root created with `contract_check_tmp=$(mktemp -d)`, delete the futex VM-free binding there, and run `check-contracts --root "$contract_check_tmp"`; expected: nonzero with `kernel.futex.contention: missing vm_free binding`. This is the required fail-closed red control. Remove that exact temporary directory after the check.

- [ ] **Step 7: Commit the enforcement ratchets**

```bash
git add crates/carrick-conformance-contract/src/bin scripts/conformance/check-contract-change.py scripts/tests/test_check_contract_change.py docs/conformance-exemptions justfile .github/workflows/ci.yml
git commit -m "ci: enforce conformance contract coverage"
```

### Task 6: Bind futex contention to VM-free semantic and structural evidence

**Files:**
- Create: `crates/carrick-kernel-example/src/contracts.rs`
- Create: `crates/carrick-kernel-example/tests/contracts.rs`
- Modify: `crates/carrick-kernel-example/src/lib.rs`
- Modify: `crates/carrick-kernel-example/src/scripted.rs`
- Modify: `crates/carrick-kernel-example/src/driver.rs`
- Modify: `crates/carrick-kernel-example/src/report.rs`
- Modify: `crates/carrick-kernel-example/Cargo.toml`
- Modify: `crates/carrick-kernel/src/dispatch/futex.rs`
- Modify: `crates/carrick-kernel/src/kernel/continuation.rs`
- Modify: `crates/carrick-kernel/Cargo.toml`
- Modify: `conformance-contracts/contracts/futex-contention.toml` only to bind measured stable metrics; do not loosen formulas

**Interfaces:**
- Consumes: `WorkMeter`, `WorkScope`, `ContractRegistry`, `ContractObservation`, and `evaluate`.
- Produces: `futex_contention_contract(scale: usize, unrelated_waiters: usize) -> Result<ContractObservation, ExampleError>` and a `RunReport::work_snapshot() -> &WorkSnapshot` accessor.

- [ ] **Step 1: Write failing VM-free contract tests**

Add tests for scale points 1, 8, 32, 128, zero wake, partial wake, and 128 unrelated waiters on another address. The main test is:

```rust
#[test]
fn futex_contention_contract_is_semantically_exact_and_linear() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry.require("kernel.futex.contention").expect("contract");
    let observations = [1, 8, 32, 128]
        .into_iter()
        .map(|scale| futex_contention_contract(scale, 0).expect("observation"))
        .collect::<Vec<_>>();
    evaluate(contract, &observations).expect("semantic and structural conformance");
}

#[test]
fn unrelated_futex_population_does_not_increase_target_queue_visits() {
    let isolated = futex_contention_contract(8, 0).expect("isolated");
    let populated = futex_contention_contract(8, 128).expect("populated");
    assert_eq!(
        isolated.work_value(WorkMetric::FutexQueueVisits),
        populated.work_value(WorkMetric::FutexQueueVisits),
    );
}
```

- [ ] **Step 2: Run the focused test and capture red evidence**

```bash
RUSTC_WRAPPER= cargo test -p carrick-kernel-example --test contracts futex_contention_contract_is_semantically_exact_and_linear -- --exact --nocapture
```

Expected: compile failure because `futex_contention_contract` and `RunReport::work_snapshot` do not exist. Preserve this transcript as the framework red-first receipt.

- [ ] **Step 3: Carry the explicit work scope through the VM-free graph**

Create one `WorkScope` in `ScriptedBackend::run_root`, place a clone in `Shared`, pass it explicitly into driver/continuation instrumentation, and snapshot it only after child joins and task-failure reconciliation. Do not use a thread-local current scope.

Increment:

- `KernelDispatches` at every dispatcher entry;
- `KernelRedispatches` only when a blocked continuation legitimately re-enters dispatch;
- `ContinuationEnrollments` when wait-service enrollment succeeds;
- `ContinuationParks` immediately before the host thread parks;
- `WakePublications` for each exact token publication;
- `ContinuationResumes` after a ready continuation is consumed;
- `FutexQueueVisits` at the queue-selection boundary, once per inspected waiter; and
- `FutexWaitersWoken` by the returned wake count.

Instrumentation must not alter locking or perform heap allocation inside futex queue traversal.

- [ ] **Step 4: Implement the reusable futex scenario**

Build the same handshake-driven waiter script used by existing semantics tests, parameterized by `scale`. Every waiter must reach `await_parked` before the wake. `unrelated_waiters` park on a different futex address and are cleaned up after the target assertions. Return semantic assertions for exact wake count, all awakened waiters completing, zero repeated redispatch while parked, and clean task retirement.

- [ ] **Step 5: Prove structural red independently**

Under `#[cfg(test)]`, add a fault-injection option to the scenario binding—not production futex code—that records one extra `FutexQueueVisits` per target waiter. Run:

```bash
CARRICK_CONTRACT_FAULT=extra-futex-visit RUSTC_WRAPPER= cargo test -p carrick-kernel-example --test contracts futex_structural_red_control -- --exact --nocapture
```

Expected: test passes only when it observes `ScalingViolation` at the smallest affected scale. Remove any environment-dependent production behavior; the red-control hook stays test-only and is itself tested as inactive by default.

- [ ] **Step 6: Run the complete VM-free gates**

```bash
RUSTC_WRAPPER= cargo test -p carrick-kernel-example --test contracts -- --nocapture
RUSTC_WRAPPER= just test-kernel
RUSTC_WRAPPER= cargo clippy -p carrick-kernel-example -p carrick-kernel --all-targets -- -D warnings
```

Expected: the contract passes all scale points, the unrelated-population invariant holds, existing semantics remain green, and clippy is clean.

- [ ] **Step 7: Commit the VM-free vertical slice**

```bash
git add Cargo.lock crates/carrick-kernel-example crates/carrick-kernel conformance-contracts/contracts/futex-contention.toml
git commit -m "test(kernel): gate futex semantics and structural scaling"
```

### Task 7: Bind signed embed semantics and separate release timing evidence

**Files:**
- Create: `crates/carrick-embed/tests/conformance_contracts.rs`
- Create: `crates/carrick-conformance-next/tests/futex_contract.rs`
- Modify: `crates/carrick-embed/Cargo.toml`
- Modify: `crates/carrick-conformance-next/Cargo.toml`
- Modify: `crates/carrick-embed/src/testing.rs`
- Modify: `crates/carrick-runtime/Cargo.toml`
- Modify: `scripts/test-signed.sh`
- Modify: `crates/carrick-embed/tests/perf_regression.rs`
- Modify: `conformance-probes/probe-inventory.json` only to add the contract ID to existing futex rows; do not alter oracle output
- Modify: `conformance-contracts/contracts/futex-contention.toml`

**Interfaces:**
- Consumes: `kernel.futex.contention`, existing `perf_futex_pingpong`, `futexpingpong`, `futexwakeexact`, `TestContainer`, `AuditObserver`, and signed test receipts.
- Produces: `TestContainer::work_scope(WorkScope)`, an instrumented signed `EmbedStructural` observation, an uninstrumented `EmbedTiming` observation, and a `carrick-conformance-next` differential test that verifies fixture and contract identity.

- [ ] **Step 1: Write failing signed-binding tests**

The structural test runs `futexwakeexact` and asserts exact semantics plus complete scoped counters. The timing test runs `perf_futex_pingpong` without `conformance-metrics`, parses at least 20 samples, loads the pinned Docker distribution/fixture identity, and evaluates the 2.0 p50 ratio. Add an explicit separation test:

```rust
#[test]
fn futex_structural_and_timing_receipts_are_distinct() {
    let structural = run_futex_structural_contract();
    let timing = run_futex_timing_contract();
    assert_eq!(structural.layer, ExecutionLayer::EmbedStructural);
    assert!(structural.work.is_some());
    assert!(structural.timing.is_none());
    assert_eq!(timing.layer, ExecutionLayer::EmbedTiming);
    assert!(timing.work.is_none());
    assert!(timing.timing.is_some());
    assert_ne!(structural.implementation_revision, "");
    assert_eq!(structural.fixture_identity, timing.fixture_identity);
}
```

- [ ] **Step 2: Compile the signed tests and capture red evidence**

```bash
RUSTC_WRAPPER= cargo test -p carrick-embed --features test-support --release --no-run
RUSTC_WRAPPER= cargo test -p carrick-conformance-next --release --no-run
```

Expected: compile failure because work-scope attachment and contract bindings do not exist.

- [ ] **Step 3: Forward instrumentation only to structural builds**

Add `conformance-metrics` features to `carrick-runtime` and `carrick-embed` that forward to `carrick-observability/conformance-metrics`. Extend `scripts/test-signed.sh` to accept `CARRICK_TEST_SIGNED_FEATURES`, validate it as a comma-separated Cargo feature list, and pass it to the build only when nonempty. The structural run sets `CARRICK_TEST_SIGNED_FEATURES=conformance-metrics`; the timing run unsets it and therefore rebuilds an uninstrumented release test executable. Record the exact enabled feature list in each signed executable receipt. A script unit test must prove the empty timing invocation emits no `--features` argument.

`TestContainer::work_scope` attaches the scope to the exact container/kernel generation and rejects reuse after retirement. The resulting observation fails if the runtime reports a different container ID or generation.

- [ ] **Step 4: Reuse existing guest probes without changing their oracle semantics**

Tag the existing `futexwakeexact`, `futexpingpong`, and `perf_futex_pingpong` inventory rows with `contract_ids = ["kernel.futex.contention"]`. The structural binding checks exact wake/park behavior from the semantic probes; the timing binding consumes the existing release probe distribution. Do not add a second futex benchmark or rewrite cached Docker output.

- [ ] **Step 5: Add source-hash and fixture identity checks**

The `carrick-conformance-next` test must require:

- the probe source hash matches the committed oracle row;
- the guest image/digest matches the contract fixture;
- musl/GNU lane selection is explicit;
- the signed executable receipt names the contract ID and exact source HEAD; and
- cleanup reports zero remaining processes.

Missing data is `IncompleteMeasurement` or `FixtureMismatch`, never a skip.

- [ ] **Step 6: Run signed structural and uninstrumented timing tests serially**

Choose unique run IDs and ensure no Carrick guest is active before rebuilding:

```bash
CARRICK_TEST_SIGNED_FEATURES=conformance-metrics CARRICK_RUN_ID=contract-futex-structural-20260919a scripts/test-signed.sh carrick-embed futex_structural_contract --exact --nocapture
env -u CARRICK_TEST_SIGNED_FEATURES CARRICK_RUN_ID=contract-futex-timing-20260919a scripts/test-signed.sh carrick-embed futex_timing_contract --exact --nocapture
CARRICK_RUN_ID=contract-futex-diff-20260919a just test-conformance-next futex_contract --nocapture
```

Expected: all semantic assertions, structural budgets, entitlement controls, artifact receipts, fixture checks, and <=2.0 p50 ratio pass. If the valid ratio is >=10x, stop and treat it as a correctness-pathology investigation; do not loosen the policy.

- [ ] **Step 7: Run the focused public probe gate**

```bash
RUSTC_WRAPPER= CARRICK_PROBE_FILTER=futexpingpong,futexwakeexact CARRICK_RUN_ID=contract-futex-probes-20260919a just conformance-probes
```

Expected: both libc rows match their committed Docker oracles, core embed cases pass, entitlement controls pass, and scoped cleanup is zero.

- [ ] **Step 8: Commit the signed bindings**

```bash
git add Cargo.lock crates/carrick-embed crates/carrick-runtime crates/carrick-conformance-next scripts/test-signed.sh conformance-probes/probe-inventory.json conformance-contracts/contracts/futex-contention.toml
git commit -m "test(embed): bind futex contract to signed and timing evidence"
```

### Task 8: Verify the complete standard, reconcile inventories, and document evidence

**Files:**
- Create: `docs/conformance-contracts/2026-09-19-futex-vertical-slice-evidence.md`
- Modify: line-pinned inventory files only through `just reconcile-inventories` after reviewing source changes
- Modify: `docs/conformance-contracts.md` only for discrepancies found during real execution

**Interfaces:**
- Consumes: every artifact from Tasks 1-7 and Carrick's existing acceptance commands.
- Produces: a clean committed branch with exact VM-free, signed embed, differential, CI, artifact-provenance, and cleanup receipts; no whole-project closure claim.

- [ ] **Step 1: Run format and focused enforcement gates**

```bash
just fmt-check
RUSTC_WRAPPER= cargo test -p carrick-conformance-contract
RUSTC_WRAPPER= cargo test -p carrick-observability --features conformance-metrics
python3 -m unittest scripts/tests/test_conformance_contract_policy.py scripts/tests/test_check_contract_change.py
RUSTC_WRAPPER= cargo run -p carrick-conformance-contract --bin check-contracts -- --root .
```

Expected: all pass.

- [ ] **Step 2: Reconcile line-pinned inventories only after the source is stable**

Run:

```bash
just reconcile-inventories
git -c core.fsmonitor=false diff -- scripts/migrate '*.json'
```

Accept only position/provenance changes caused by the committed edits. If a semantic classification changes, edit and review that inventory deliberately instead of using reconciliation to bless it.

- [ ] **Step 3: Run broad host and VM-free gates**

```bash
RUSTC_WRAPPER= just test-kernel
RUSTC_WRAPPER= just test
RUSTC_WRAPPER= just ci
```

Expected: all exit zero. Preserve complete logs rather than truncating them.

- [ ] **Step 4: Run the signed promotion ladder on one exact artifact**

Ensure no build runs concurrently with a guest. Build/sign once, record source HEAD, binary SHA-256, CDHash, LC_UUID, entitlement, and `__dof_carrick`, then run:

```bash
CARRICK_RUN_ID=contract-final-probes-20260919a just conformance-probes
CARRICK_RUN_ID=contract-final-smoke-20260919a just --no-deps conformance smoke
CARRICK_RUN_ID=contract-final-full-20260919a just --no-deps conformance
```

After each rung, verify the binary identity is unchanged and run `scripts/sudo/kill.sh` with that rung's exact `contract-final-*-20260919a` ID to prove scoped cleanup. Any red rung stops promotion.

- [ ] **Step 5: Write the evidence receipt**

Create `docs/conformance-contracts/2026-09-19-futex-vertical-slice-evidence.md` with:

- contract ID and registry digest;
- semantic and structural red-first transcripts;
- scale-point observations and evaluated formulas;
- signed structural and uninstrumented timing observations;
- Docker fixture/image identity and ratio distribution;
- final source HEAD and signed artifact provenance;
- exact commands and exit statuses;
- cleanup results; and
- explicit statement that one futex contract does not close the frozen 2,127-suite or <=2x ecosystem denominator.

- [ ] **Step 6: Run final diff and status checks**

```bash
git diff --check
git -c core.fsmonitor=false status --short
git -c core.fsmonitor=false diff --stat HEAD~8..HEAD
```

Expected: only intended changes; no build products, temporary receipts, or unrelated files.

- [ ] **Step 7: Commit evidence and any mechanical inventory reconciliation**

Use a separate mechanical commit if inventories changed:

```bash
git add scripts/migrate
git commit -m "chore: reconcile conformance contract inventories"
```

Then commit the evidence:

```bash
git add docs/conformance-contracts/2026-09-19-futex-vertical-slice-evidence.md docs/conformance-contracts.md
git commit -m "docs: record futex conformance contract evidence"
```

- [ ] **Step 8: Request whole-branch review**

Ask the reviewer to verify the actual diff against the spec, with special attention to product feature closure, counter isolation, budget provenance, timing/instrumentation separation, ratchet false negatives, signed artifact identity, and preservation of existing gates. Fix every concrete finding and rerun the affected focused and broad gates before integration.
