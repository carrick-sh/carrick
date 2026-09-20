# Contract-Driven Conformance Investigations

This guide is the operational manual for autonomous and assisted conformance investigations in Carrick. It implements the standard defined in [docs/superpowers/specs/2026-09-20-contract-driven-investigation-design.md](superpowers/specs/2026-09-20-contract-driven-investigation-design.md).

---

## Purpose

Reduce the time between an ecosystem or LTP conformance failure and a precise, failing conformance contract. The workflow enforces:

1. **Cheapest capable layer first:** Non-VMM kernel verification (`carrick-kernel-example`) must be attempted and evaluated before escalating to guest execution (`carrick-embed`) or hypervisor lanes.
2. **Red-first evidence:** Every diagnosis requires verified red evidence demonstrating failure detection against a known-bad implementation.
3. **Phase isolation:** Carrick guest runs and Docker oracle runs never overlap across any checkouts on the host.
4. **Finite campaign budgets:** Unattended investigations operate under strict limits; exhausting a budget parks the investigation cleanly without losing state or releasing unsafe leases.
5. **Clear human review boundary:** Autonomous investigations produce a complete review package with an evidence-backed diagnosis and proposed fix; they do not mutate production code.

---

## The Investigation Lifecycle

Investigations progress through a durable, event-sourced state machine:

```text
queued -> classified -> reducing -> diagnosing -> review-ready
   |          |           |           |
   +----------+-----------+-----------+---> parked ---> (resumed)
```

### Stage Invariants

| Stage | Prerequisites & Invariants |
|---|---|
| `queued` | Intake of candidate failure from conformance results or manual selection. Records run ID, suite, test ID, and binary SHA. |
| `classified` | Mandatory contract lookup and non-VMM capability decision (`VmFreeExisting`, `VmFreeExtension`, or `RequiresGuest`). An unsupported harness feature cannot be falsely classified as `RequiresGuest`. |
| `reducing` | Minimal reproduction in the cheapest capable layer. Must preserve named semantic and structural mechanisms connecting it to the original failure. |
| `diagnosing` | Meaningful red evidence against a known-bad revision, active fixture verification, and experiments discriminating competing hypotheses. |
| `review-ready` | Complete review package (`ReviewPackage`) containing failing contract, failing claim, Linux semantic authority citation, diagnosis, proposed correction, affected invariants, and open higher-layer gates. |
| `parked` | Enters on budget exhaustion or external obstruction. Preserves consumed budget, hypotheses, and a concrete resumption condition. Releases coordinator leases. |

---

## Resource Coordinator (`carrick-coordinator`)

The host-wide coordinator manages advisory resource leases under `$TMPDIR/carrick-coordinator/locks/` using POSIX `flock` and PID liveliness probes (`kill(pid, 0) == ESRCH`).

### Conflict Rules

- `SignedGuestRun` and `DockerPhase` are **strictly mutually exclusive**. Carrick and Docker never run concurrently.
- `TimingWindow` requires an exclusive, quiet host; all other resource classes (`Build`, `SignedGuestRun`, `DockerPhase`, `TracingSession`) are excluded.
- `Build` excludes `SignedGuestRun` to prevent replacing a binary beneath an active run.
- Stale leases are automatically reaped during acquisition if the owning PID is dead (`ESRCH`). Elapsed time alone never forces a lease release.

---

## Syscall Inventory & Claim Model

The syscall inventory (`conformance-contracts/inventory.json`) is generated from the authoritative 463 AArch64 syscall table in `carrick-abi`:

- **Bring-Up:** Calls emulated in Carrick. Must be mapped to explicit claims or enumerated in `uncovered_behaviors`.
- **Deferred:** Calls explicitly not emulated (e.g. `io_uring`). Covered by claims asserting declared refusal errnos (e.g. `ENOSYS`).
- **Planned:** Reserved calls intended for future emulation.

Each claim records its `CapabilityClass` and `CoverageState` (`Declared`, `Bound`, `Evidenced`, or `ViolationDemonstrated`).

---

## Commands and Recipes

### 1. Inventory Management

Generate or check the syscall inventory:

```sh
# Generate fresh inventory.json and report summary
just inventory

# Check for drift between checked-in inventory and ABI table
just check-inventory
```

### 2. Running Investigations

Manage investigations through the CLI:

```sh
# Start an investigation from recent conformance results
just investigate new --from-results target/conformance/results.hvf.full.jsonl --suite ltp-connect01

# Manually initiate an investigation
just investigate new --id inv-connect --suite ltp-connect01 --test-id connect01 --run-id conf-100-c01

# View investigation status
just investigate status
just investigate status --id inv-connect

# Park an investigation
just investigate park --id inv-connect --reason "Waiting on upstream network review"

# Resume an investigation
just investigate resume --id inv-connect
```

---

## Pilot Investigation Case Study: `ltp-connect01`

The pilot investigation for this system evaluated `ltp-connect01`, a known divergence where Carrick failed 1 of 7 tests while Docker passed all 7:

1. **Intake:** Ingested from `scripts/conformance/baseline.jsonl` where `carrick` reported `failure` and `docker` reported `success`.
2. **Classification:** Determined that `AF_UNIX` stream socket connection refusal does not require hypervisor virtualization: classified as `VmFreeExisting` through `carrick-kernel-example::socket_connect`.
3. **Reduction:** Reduced to a minimal two-task fixture preserving `socket_connect_immediate_refusal` and `unconnected_state_settlement`.
4. **Diagnosis:** Formulated hypothesis H1 (unconditional asynchronous wait enrollment). Attached red evidence demonstrating `connect01` test 7 expected `ECONNREFUSED (111)` but received `EINPROGRESS (115)`.
5. **Review Ready:** Produced review package detailing root cause in `crates/carrick-kernel/src/dispatch/net.rs`, proposed fix to inspect listener backlog readiness before continuation enrollment, and specified validation plan.
