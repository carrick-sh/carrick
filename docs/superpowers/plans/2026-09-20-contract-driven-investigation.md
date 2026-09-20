# Contract-Driven Investigation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans if the owner later authorizes implementation. Steps use checkbox syntax for tracking. **The current request authorizes planning only. Do not execute these steps, change code, run builds/tests, or commit as part of preparing this plan.**

**Goal:** Reduce the time between an ecosystem failure and a precise failing conformance contract by establishing an autonomous, contract-driven investigation workflow: generating a complete syscall inventory from the authoritative ABI table, enforcing stateful investigation progression through durable records, coordinating host resource leases to prevent Carrick‖Docker interference, and completing an end-to-end pilot on a real conformance failure.

**Architecture:**
- **Claim & Capability Model (`carrick-conformance-contract`)**: Extends the contract specification with fine-grained behavioral claims, non-VMM capability classifications (`VmFreeExisting`, `VmFreeExtension`, `RequiresGuest`), and multi-state evidence ladders (`Declared`, `Bound`, `Evidenced`, `ViolationDemonstrated`). Generates a complete syscall inventory against `carrick-abi`'s 463 AArch64 syscall table.
- **Resource Coordinator (`carrick-coordinator`)**: Host-wide advisory lock service under `$TMPDIR/carrick-coordinator/` using POSIX `flock` and PID liveness verification (`kill(pid, 0)`). Strictly enforces phase mutual exclusion (Carrick guest execution and Docker oracle runs never overlap; timing windows require quiet hosts; builds do not replace active artifacts).
- **Investigation Engine (`carrick-investigation`)**: Durable, event-sourced JSONL engine under `target/investigations/` driving validated stage transitions: `queued -> classified -> reducing -> diagnosing -> review-ready` (with safe `parked` states on budget exhaustion).
- **Intake & Expansion**: Parses machine-readable conformance results, ranks semantic defects and operational pathologies, enforces campaign budgets, and generates new claim descriptors prioritised by failure clusters.

**Tech Stack:** Rust 2024 (1.96.0 pin), `serde`/`toml`/`thiserror`, `carrick-abi`, `carrick-conformance-contract`, `carrick-conformance`, `carrick-kernel-example`, `carrick-embed`, POSIX file locks, JSON Lines (`serde_json`), `just`.

**Spec:** [docs/superpowers/specs/2026-09-20-contract-driven-investigation-design.md](../specs/2026-09-20-contract-driven-investigation-design.md).

**Inspected base:** `265d401ea87943c5493fc1764e209a7cbf91041a`.
**Status:** Approved implementation plan.

---

## Global Constraints

- **Normative definition of correctness:** Linux semantics plus non-pathological operational complexity (bounded work and runtime ratios per `docs/conformance-contracts.md`). A semantic pass never excuses a structural-budget or runtime-ratio failure.
- **Cheapest capable layer:** Investigations must attempt reduction in the cheapest layer (`VmFree` via `carrick-kernel-example`) before escalating to guest execution (`carrick-embed`) or full CLI execution. An unsupported harness capability must be classified as `VmFreeExtension` rather than falsely labeled `RequiresGuest`.
- **Phase isolation:** Carrick guest runs and Docker oracle runs must NEVER run concurrently. `carrick-coordinator` enforces this across all participating checkouts.
- **Durable records:** Investigation state transitions are recorded as an append-only event stream in JSONL. Resumption from a parked state requires validating that existing evidence and artifact identities remain consistent.
- **Budget enforcement:** Campaign budgets (max experiments, wall-clock time, resource units) are checked at experiment boundaries. Exceeding a budget *parks* the investigation; it never converts a failure into a skip or pass.
- **Safety and codesigning:** macOS HVF guest runs require `com.apple.security.hypervisor` entitlement. Rebuilding runtime code requires rebuilding `-p carrick-cli` and resigning (`scripts/build-signed.sh`). Cargo test executables for guest execution run through `scripts/test-signed.sh`.
- **Review boundary:** Autonomous investigations produce a review package containing a replayable failing contract, Linux authority, diagnosis, proposed correction, and validation plan. Autonomous agents do NOT apply production code corrections.

---

## File Responsibilities

| Area | Path | Responsibility |
|---|---|---|
| Contract Model | `crates/carrick-conformance-contract/src/model.rs` | `ClaimId`, `Claim`, `CapabilityClass`, `CoverageState`, descriptor types |
| Registry | `crates/carrick-conformance-contract/src/registry.rs` | Loads contracts from `contracts/*.toml` and claims from `claims/*.toml` |
| Syscall Inventory | `crates/carrick-conformance-contract/src/inventory.rs` | Cross-references `carrick-abi` syscall table against claims |
| Inventory Generator | `crates/carrick-conformance-contract/src/bin/generate-inventory.rs` | CLI emitting `conformance-contracts/inventory.json` |
| Contract Linter | `crates/carrick-conformance-contract/src/bin/check-contracts.rs` | Enforces complete inventory coverage and claim binding validity |
| Initial Claims | `conformance-contracts/claims/*.toml` | Declarations for existing 11 contracts with honest coverage states |
| Coordinator Crate | `crates/carrick-coordinator/` | New crate: advisory resource locking, phase exclusion, crash recovery |
| Coordinator Core | `crates/carrick-coordinator/src/coordinator.rs` | `Coordinator`, `Lease`, `ResourceClass`, `LeaseOwner`, flock mechanics |
| Campaign Budgets | `crates/carrick-coordinator/src/budget.rs` | `CampaignBudget`, `CampaignState`, experiment counting, bounded cleanup |
| Investigation Crate | `crates/carrick-investigation/` | New crate: state machine, event-log persistence, review packaging |
| Investigation Record | `crates/carrick-investigation/src/record.rs` | `Investigation`, `InvestigationId`, `ArtifactIdentities`, `Hypothesis` |
| Stage Transitions | `crates/carrick-investigation/src/stage.rs` | Stage enum, transition guards, prerequisite verification |
| Experiments | `crates/carrick-investigation/src/experiment.rs` | `ExperimentPlan`, `ExperimentResult`, separating observation from inference |
| Review Package | `crates/carrick-investigation/src/review.rs` | `ReviewPackage`, `Diagnosis`, `ProposedCorrection`, validation steps |
| Persistence | `crates/carrick-investigation/src/persistence.rs` | Event-sourced append-only JSONL storage under `target/investigations/` |
| Conformance Intake | `crates/carrick-investigation/src/intake.rs` | Ingests `results.*.jsonl`, prioritizes semantic and ratio anomalies |
| Investigation CLI | `crates/carrick-investigation/src/bin/investigate.rs` | CLI driving investigations (`new`, `transition`, `park`, `resume`, `review`) |
| Conformance Harness | `crates/carrick-conformance/src/main.rs` | Wires coordinator leases into Carrick and Docker execution phases |
| Recipes | `justfile` | Adds `just inventory`, `just investigate`, `just check-inventory` |

---

## Interface Decisions to Implement

```rust
// --- crates/carrick-conformance-contract/src/model.rs ---

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClaimId(String);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub id: ClaimId,
    pub contract: ContractId,
    pub description: String,
    pub linux_authority: Vec<String>,
    #[serde(default)]
    pub fixture_requirements: Vec<String>,
    #[serde(default)]
    pub related_contracts: Vec<ContractId>,
    #[serde(default)]
    pub related_ecosystem_rows: Vec<String>,
    pub capability: CapabilityClass,
    pub coverage: CoverageState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CapabilityClass {
    VmFreeExisting { capability: String },
    VmFreeExtension { capability: String, rationale: String },
    RequiresGuest { rationale: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CoverageState {
    Declared,
    Bound { layer: ExecutionLayer },
    Evidenced { layer: ExecutionLayer, revision: String },
    ViolationDemonstrated { layer: ExecutionLayer, known_bad_revision: String },
}

// --- crates/carrick-coordinator/src/coordinator.rs ---

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceClass {
    Build,
    SignedGuestRun,
    DockerPhase,
    TracingSession,
    TimingWindow,
}

pub struct Coordinator {
    lock_dir: PathBuf,
}

impl Coordinator {
    pub fn new(lock_dir: PathBuf) -> Result<Self, CoordinatorError>;
    pub fn acquire(&self, resource: ResourceClass, owner: LeaseOwner) -> Result<Lease, CoordinatorError>;
    pub fn try_acquire(&self, resource: ResourceClass, owner: LeaseOwner) -> Result<Option<Lease>, CoordinatorError>;
    pub fn recover_stale_leases(&self) -> Result<usize, CoordinatorError>;
}

// --- crates/carrick-investigation/src/stage.rs ---

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "stage", rename_all = "kebab-case")]
pub enum Stage {
    Queued,
    Classified {
        contract: ContractId,
        capability: CapabilityClass,
    },
    Reducing {
        layer: ExecutionLayer,
        preserved_mechanisms: Vec<String>,
    },
    Diagnosing {
        red_evidence: Vec<String>,
        fixture_active: bool,
    },
    ReviewReady {
        review_package_path: PathBuf,
    },
    Parked {
        prior_stage: Box<Stage>,
        obstruction: String,
        consumed_budget: ResourceUsage,
        resumption_condition: String,
    },
}
```

---

## Task 1: Claim and Capability Model Extension in `carrick-conformance-contract`

**Files:**
- Modify: `crates/carrick-conformance-contract/Cargo.toml`
- Modify: `crates/carrick-conformance-contract/src/model.rs`
- Modify: `crates/carrick-conformance-contract/src/registry.rs`
- Modify: `crates/carrick-conformance-contract/src/lib.rs`
- Create: `crates/carrick-conformance-contract/tests/claims.rs`

**Consumes:** Existing `ContractId`, `ExecutionLayer`, `ConformanceContract`.
**Produces:** Validated `ClaimId`, `Claim`, `CapabilityClass`, `CoverageState`, and claim registry loading.

- [ ] **Step 1: Write failing unit tests for claim model**

Create `crates/carrick-conformance-contract/tests/claims.rs` validating:
- `ClaimId` parsing: accepts lowercase alphanumeric parts with periods (e.g. `kernel.futex.contention.wake-cardinality`), rejects invalid formats.
- `CapabilityClass` and `CoverageState` serialization/deserialization to TOML and JSON.
- `CoverageState::ViolationDemonstrated` mandates a non-empty `known_bad_revision`.

- [ ] **Step 2: Implement claim types in `model.rs`**

Add `ClaimId`, `Claim`, `CapabilityClass`, and `CoverageState` to `crates/carrick-conformance-contract/src/model.rs`. Re-export in `lib.rs`.

- [ ] **Step 3: Extend `ContractRegistry` to load claims**

In `crates/carrick-conformance-contract/src/registry.rs`:
- Look for `claims/*.toml` under `conformance-contracts/claims/`.
- Validate that every claim references a registered `ContractId`.
- Ensure no duplicate `ClaimId`s exist.
- Add `registry.claims() -> impl ExactSizeIterator<Item = &Claim>` and `registry.get_claim(&ClaimId)`.

- [ ] **Step 4: Verify with `cargo test`**

Run:
```sh
cargo test -p carrick-conformance-contract --test claims
```
Ensure all tests exit 0.

---

## Task 2: Syscall Inventory Generator and Initial Claim Corpus

**Files:**
- Modify: `crates/carrick-conformance-contract/Cargo.toml` (add dependency on `carrick-abi`)
- Create: `crates/carrick-conformance-contract/src/inventory.rs`
- Create: `crates/carrick-conformance-contract/src/bin/generate-inventory.rs`
- Modify: `crates/carrick-conformance-contract/src/bin/check-contracts.rs`
- Create: `conformance-contracts/claims/fork.toml`
- Create: `conformance-contracts/claims/futex.toml`
- Create: `conformance-contracts/claims/inotify.toml`
- Create: `conformance-contracts/claims/scheduler.toml`
- Create: `crates/carrick-conformance-contract/tests/inventory.rs`

**Consumes:** `carrick_abi::syscall::aarch64_table()`, `ContractRegistry`.
**Produces:** `SyscallInventory`, `conformance-contracts/inventory.json`, and initial claims for all 11 existing contracts.

- [ ] **Step 1: Write failing tests for inventory generation**

Create `crates/carrick-conformance-contract/tests/inventory.rs`:
- Assert inventory covers all 463 syscall table entries.
- Verify `BringUp`, `Deferred`, and `Planned` counts match `carrick-abi`.
- Assert each entry accurately lists associated claims from the registry.

- [ ] **Step 2: Implement `inventory.rs`**

In `crates/carrick-conformance-contract/src/inventory.rs`:
- Map every `Syscall` from `carrick_abi::syscall::aarch64_table()`.
- Scan claims for matching syscall surface references (e.g. `syscall:futex` -> matches `futex`).
- Compute `InventorySummary`: total, bring_up, deferred, planned, with_claims, uncovered.
- Provide JSON serialization for durable artifact generation.

- [ ] **Step 3: Create initial claim descriptors**

Translate the 11 existing contracts into explicit claims under `conformance-contracts/claims/`:
- `claims/fork.toml`: filetable copying, mapping projection, stage1 image recycling.
- `claims/futex.toml`: wake cardinality, queue visits, requeue batching.
- `claims/inotify.toml`: watch registration, queue readiness scaling.
- `claims/scheduler.toml`: host-wait handoff, preemption progress, preemption cost.
Mark states honestly: `CoverageState::Evidenced` for layers with green tests; `CoverageState::Declared` where no test currently runs.

- [ ] **Step 4: Implement `generate-inventory.rs` and update `check-contracts.rs`**

- `generate-inventory.rs`: writes `conformance-contracts/inventory.json` and prints summary.
- `check-contracts.rs`: add verification that `conformance-contracts/inventory.json` is fresh and that no declared claims point to nonexistent contracts or broken surfaces.

- [ ] **Step 5: Verify inventory generation and lint gate**

Run:
```sh
cargo run -p carrick-conformance-contract --bin generate-inventory
cargo test -p carrick-conformance-contract --test inventory
cargo run -p carrick-conformance-contract --bin check-contracts
```
Ensure all exit 0.

---

## Task 3: Host-Wide Resource Coordinator (`carrick-coordinator`)

**Files:**
- Create: `crates/carrick-coordinator/Cargo.toml`
- Create: `crates/carrick-coordinator/src/lib.rs`
- Create: `crates/carrick-coordinator/src/coordinator.rs`
- Create: `crates/carrick-coordinator/src/budget.rs`
- Create: `crates/carrick-coordinator/tests/exclusion.rs`
- Create: `crates/carrick-coordinator/tests/crash_recovery.rs`
- Modify: `Cargo.toml` (add workspace member `crates/carrick-coordinator`)
- Modify: `crates/carrick-conformance/src/main.rs`

**Consumes:** POSIX `flock`, `kill(pid, 0)` for process probing, `CARRICK_RUN_ID`.
**Produces:** `Coordinator` guaranteeing Carrick and Docker mutual exclusion and crash recovery.

- [ ] **Step 1: Create `carrick-coordinator` crate scaffolding**

Initialize `crates/carrick-coordinator/Cargo.toml` with `serde`, `serde_json`, `thiserror`, `nix` (or `libc` for `flock` and `kill`). Add to workspace `Cargo.toml`.

- [ ] **Step 2: Write failing tests for mutual exclusion and crash recovery**

In `crates/carrick-coordinator/tests/`:
- `exclusion.rs`: prove that while `SignedGuestRun` lease is held, acquiring `DockerPhase` returns `Err` or blocks; prove `TimingWindow` excludes all other classes.
- `crash_recovery.rs`: write a mock lease file with a nonexistent PID (`kill(pid, 0) == ESRCH`); verify `recover_stale_leases()` reaps the lease and allows new acquisition.

- [ ] **Step 3: Implement `Coordinator` and file-locking mechanics**

In `crates/carrick-coordinator/src/coordinator.rs`:
- Base lock path: `$TMPDIR/carrick-coordinator/locks/`.
- Lock files: `build.lock`, `guest_run.lock`, `docker.lock`, `timing.lock`, `trace.lock`.
- Conflict matrix:
  - `DockerPhase` conflicts with `SignedGuestRun`, `TimingWindow`.
  - `SignedGuestRun` conflicts with `DockerPhase`, `Build`, `TimingWindow`.
  - `TimingWindow` conflicts with all classes.
- Metadata: write JSON sidecar `<resource>.lease.json` recording `LeaseOwner { host, pid, run_id, investigation_id }`.

- [ ] **Step 4: Implement `CampaignBudget`**

In `crates/carrick-coordinator/src/budget.rs`:
- Track `experiments_run`, `elapsed_duration`, `resource_units`.
- Provide `check_budget() -> Result<(), BudgetExhausted>`.
- Provide `in_flight_cleanup(run_id)` calling `scripts/sudo/kill.sh <run-id>` on limits.

- [ ] **Step 5: Wire coordinator into `carrick-conformance`**

In `crates/carrick-conformance/src/main.rs`:
- Phase 1 (Carrick execution): acquire `SignedGuestRun` lease before starting; release at Phase 1 end.
- Phase 2 (Docker execution): acquire `DockerPhase` lease before running containers; release at Phase 2 end.

- [ ] **Step 6: Verify coordinator tests**

Run:
```sh
cargo test -p carrick-coordinator
```
Ensure all exit 0.

---

## Task 4: Durable Investigation Engine (`carrick-investigation`)

**Files:**
- Create: `crates/carrick-investigation/Cargo.toml`
- Create: `crates/carrick-investigation/src/lib.rs`
- Create: `crates/carrick-investigation/src/record.rs`
- Create: `crates/carrick-investigation/src/stage.rs`
- Create: `crates/carrick-investigation/src/experiment.rs`
- Create: `crates/carrick-investigation/src/review.rs`
- Create: `crates/carrick-investigation/src/persistence.rs`
- Create: `crates/carrick-investigation/src/intake.rs`
- Create: `crates/carrick-investigation/src/bin/investigate.rs`
- Create: `crates/carrick-investigation/tests/lifecycle.rs`
- Create: `crates/carrick-investigation/tests/transition_guards.rs`
- Modify: `Cargo.toml` (add workspace member `crates/carrick-investigation`)

**Consumes:** `carrick-conformance-contract`, `carrick-coordinator`, conformance results JSONL.
**Produces:** State machine and CLI for managing durable investigations.

- [ ] **Step 1: Create `carrick-investigation` crate scaffolding**

Initialize `crates/carrick-investigation/Cargo.toml` with dependencies on `carrick-conformance-contract`, `carrick-coordinator`, `serde`, `serde_json`, `chrono`, `thiserror`.

- [ ] **Step 2: Write failing tests for stage transitions and guards**

In `crates/carrick-investigation/tests/`:
- `transition_guards.rs`:
  - `Queued -> Classified` fails if no contract or capability classification is supplied.
  - `Classified -> Reducing` fails if layer chosen is not the cheapest capable layer.
  - `Reducing -> Diagnosing` fails without verified red evidence.
  - `Diagnosing -> ReviewReady` fails without review package contents.
  - Park and resume preserve full history.
- `lifecycle.rs`: test full progression from intake through review package assembly.

- [ ] **Step 3: Implement `stage.rs` and `record.rs`**

- `stage.rs`: define `Stage` enum and `transition(from, to, evidence)` validating all prerequisites.
- `record.rs`: define `Investigation`, `SelectedFailure`, `Hypothesis`, `ResourceUsage`.

- [ ] **Step 4: Implement event-sourced persistence (`persistence.rs`)**

- Append-only JSONL files under `target/investigations/{id}.jsonl`.
- Define `InvestigationEvent` enum (`Created`, `StageChanged`, `ExperimentRecorded`, `Parked`, `Resumed`).
- Implement `load(id) -> Result<Investigation>` by replaying events.

- [ ] **Step 5: Implement `intake.rs`, `experiment.rs`, and `review.rs`**

- `intake.rs`: parse `results.*.jsonl` from `carrick-conformance`, extract failed rows, filter by suite or severity.
- `experiment.rs`: structure `ExperimentPlan` and `ExperimentResult`, separating direct observation from inference.
- `review.rs`: assemble `ReviewPackage` with failing contract, Linux authority citation, diagnosis, proposed fix, and open gates.

- [ ] **Step 6: Implement CLI binary `investigate.rs`**

Provide CLI commands:
- `investigate new --from-results <file> --suite <name>`
- `investigate transition --id <id> --to <stage>`
- `investigate park --id <id> --reason <text>`
- `investigate resume --id <id>`
- `investigate status [--id <id>]`

- [ ] **Step 7: Verify investigation engine tests**

Run:
```sh
cargo test -p carrick-investigation
```
Ensure all tests exit 0.

---

## Task 5: End-to-End Pilot Investigation Walkthrough

**Files:**
- Output: `target/investigations/pilot-investigation.jsonl`
- Create: `crates/carrick-investigation/tests/pilot_walkthrough.rs`

**Consumes:** Live or captured real conformance failure from `scripts/conformance/baseline.jsonl`.
**Produces:** Complete, verified investigation through `ReviewReady` status demonstrating the non-VMM decision, red contract, and review package.

- [ ] **Step 1: Select real pilot failure and write regression integration test**

Select an actual conformance gap or regression (e.g. from `baseline.jsonl` or LTP socket/signal suite). Construct `crates/carrick-investigation/tests/pilot_walkthrough.rs` simulating the full agent-driven progression:
1. Ingest failure into `Stage::Queued`.
2. Classify: verify non-VMM capability decision (`VmFreeExisting` or `VmFreeExtension`).
3. Reduce: create a minimal reproduction in `carrick-kernel-example`.
4. Diagnose: capture red contract observation against the failure, test alternative hypotheses.
5. Review: assemble and emit the review package.

- [ ] **Step 2: Execute pilot walkthrough test**

Run:
```sh
cargo test -p carrick-investigation --test pilot_walkthrough -- --nocapture
```
Confirm the test creates the durable record, validates all stage invariants, and produces a complete review package without human prompts or workarounds.

---

## Task 6: Recipes, Documentation, and Gate Integration

**Files:**
- Modify: `justfile`
- Modify: `crates/README.md`
- Create: `docs/investigations.md`

**Consumes:** Tasks 1-5 artifacts and binaries.
**Produces:** Repository workflow integration and documentation.

- [ ] **Step 1: Update `justfile`**

Add recipes:
```just
# Conformance contract and investigation recipes
inventory:
    cargo run -p carrick-conformance-contract --bin generate-inventory

check-inventory:
    cargo run -p carrick-conformance-contract --bin generate-inventory -- --check

investigate *ARGS:
    cargo run -p carrick-investigation --bin investigate -- {{ARGS}}
```
Integrate `check-inventory` into `just ci`.

- [ ] **Step 2: Document architecture and usage in `docs/investigations.md`**

Document:
- Investigation lifecycle and stage rules.
- How to run `carrick-investigation`.
- Coordinator leases and manual lease recovery (`kill.sh`).
- Pilot findings and post-pilot workflow.

- [ ] **Step 3: Update `crates/README.md`**

Add `carrick-coordinator` and `carrick-investigation` to the crate table and layer dependency map.

- [ ] **Step 4: Run full repository verification**

Run:
```sh
just fmt-check
just clippy
just check-matrix
just test
```
Verify every gate passes cleanly.

---

## Review Focus & Acceptance Assertions

1. **Inventory completeness:** Every single one of the 463 AArch64 syscalls in `carrick-abi` must appear in `inventory.json` with an explicit support level and claim mapping or explicit gap note.
2. **Phase mutual exclusion:** A test attempting to acquire a Docker lease while a Carrick guest lease is active must never succeed.
3. **Stage guard fail-closed behavior:** Transitioning to `Diagnosing` without verified red evidence, or to `ReviewReady` with unexecuted required layers, must return a descriptive error and prevent stage advancement.
4. **Crash recovery safety:** Stale leases are reaped ONLY when `kill(pid, 0) == ESRCH`. Elapsed time alone never forces a lease release.
5. **Durable persistence:** Terminating an investigation mid-flight and reloading it from JSONL restores the exact stage, hypotheses, and evidence references.
