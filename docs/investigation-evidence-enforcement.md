# Investigation evidence enforcement and write/seek pilot

The investigation CLI now requires an explicit capability decision. A VM-free
classification cannot reduce through a guest layer. Diagnosis consumes receipt
paths, not prose, and review consumes a validated JSON ReviewPackage whose claim
belongs to the measured contract and whose causal evidence references its receipts.
Legacy narrative-only investigations must be reduced again; they cannot be
promoted by adding an arbitrary review filename.

`investigate run-write-seek --output <new-directory>` builds and runs the
registered VM-free producer with conformance metrics enabled. It captures both
streams, executable SHA-256, source revision and a digest of tracked and untracked
crate/contract/build inputs. Dirty source is included. Diagnosis revalidates these
identities, fixture activity, layer, fixture identity, scale and typed evaluator
failure. A green run, missing binding, unknown measurement or changed output is
not red evidence. Receipts are local evidence, not tamper-proof attestations.

The receipt runner currently supports only this registered VM-free pilot through
the CLI. Other signed/guest producers need their own artifact and cleanup adapters;
unsupported receipt layers fail closed. The underlying capture API is a trusted
local tool, not a sandbox for arbitrary executables. Do not use it for guests or
process-spawning producers. The pilot's 30-second execution budget kills and reaps
the direct producer. Its build uses Cargo's ordinary lifecycle. No unattended
campaign budget/scheduler completeness is claimed by this change.

The pilot acquires a coordinator window around build and execution. Existing
coordination is cooperative. This change does not qualify arbitrary unmanaged
builds, timing measurements, or the coordinator's cross-process crash behavior.

## What the pilot proves

`kernel.fs.write-seek` drives the real kernel dispatcher with HostFsBackend:
create a regular non-append file, repeat write(64 bytes)/lseek(0, SEEK_SET), read
back the bytes, close and exit. Completion counts independently establish fixture
activity at 1, 8, 32 and 128 iterations. The execution-scoped metric
`host_write_position_queries` counts actual preparatory host SEEK_CUR calls at
both scalar-write query sites, and is disabled with ordinary conformance metrics.

The contract budgets zero such queries only for this offset-zero, unlimited-file-
size, no-sparse-extents fixture. This is an architectural work requirement, not a
claim that Linux mandates any particular host implementation. Linux write/lseek
semantics remain the return-value, offset and content authority. It isolates one
mechanism reported in inotify09's thread B; it does not reproduce the complete
inotify workload, prove the claimed 35-microsecond timing, or close its 2x gate.

The signed binding now executes the `writeseek` guest probe on a fresh writable
host-backed mount at every scale. It requires an explicit source SHA-256 and a
digest-pinned image, rejects missing or malformed output, records the actual work
scope, and shuts down each carrier before starting the next. Observation capture
and strict budget evaluation are separate tests: successful capture is not a
budget pass. `investigate source-identity` computes the source digest for this run.

The same probe is registered in conformance-next with source-hashed native ARM64
Docker oracle output for musl and GNU libc. Oracle observations at all four scales
are retained under `target/investigations/write-seek-bindings/`, with commands,
image identity and executable hashes in `docker-receipts.json`. This is semantic
evidence; Docker does not measure Carrick's internal work counter. Signed receipts
are not yet accepted by the investigation CLI's VM-free receipt adapter.

Inotify's existing watch and readiness claims describe their real VM-free
capability, with coverage marked bound rather than unverified HEAD execution
evidence. Registration and semantic parity alone do not establish signed budget
acceptance or the full workload's runtime ratio.

## Review boundary

A proposed offset-query optimization must account for shared open-description
state, dup/fork aliases, append changes, seek beyond EOF, subsequent truncation,
finite RLIMIT_FSIZE and sparse extents. A boolean meaning 'never sought past EOF'
is not by itself proof that the current offset cannot exceed a subsequently
truncated length. Require semantic regressions for these transitions before
accepting the production correction. This investigation leaves that correction
unimplemented and preserves the pre-existing runtime work.

## Verification scope

The transition regressions were witnessed red before enforcement: prose evidence,
VM-free-to-guest escalation, and a nonexistent review package all incorrectly
advanced. The fixed tests reject all three. Receipt tests run a real local
producer fixture and reject changed source, altered output, inactive fixtures,
and green observations. These tooling fixtures are explicitly not the pilot.
The real pilot runs the kernel's write and lseek operations and reads actual bytes.

Pre-existing `sought_past_eof` fields/methods remain unused and produce warnings.
An existing temporary-borrow error in `with_recorded_fd_open_path` was corrected
by retaining the captured table while its path guard lives. This compile-only
repair remains alongside the user's existing uncommitted method.

The strict `check-contracts` registration check now passes with real embed and
Docker bindings. The zero-query structural budget is unchanged. A binding-presence
regression was witnessed red before these bindings were added, then green. The
registry check establishes binding completeness, not an execution verdict.

## Running the signed reduction

Build both `writeseek` guest libc variants and obtain the native ARM64 image's
verified digest before running this sequence. Set `CARRICK_WRITE_SEEK_IMAGE` to
that digest-pinned reference; a mutable tag is rejected. Run Docker observations
in a separate phase from Carrick execution.

```sh
export CARRICK_OBSERVATION_SOURCE="$(target/debug/investigate source-identity)"
export CARRICK_TEST_SIGNED_FEATURES=conformance-metrics
export CARRICK_CONTRACT_ID=kernel.fs.write-seek
export CARRICK_RUN_ID=write-seek-capture
export CARRICK_WRITE_SEEK_OBSERVATIONS="$PWD/target/write-seek-observations.json"
RUSTC_WRAPPER= scripts/test-signed.sh carrick-embed write_seek_contract_observations --exact --nocapture
```

The signer records executable identities, entitlement checks, its negative
control and scoped cleanup in
`target/test-results/carrick-embed-signed-artifacts.jsonl`. Preserve that receipt
alongside the source digest, both probe executable hashes, image digest and
observations. Run `write_seek_contract_budget --exact --nocapture --test-threads=1`
on the same signed test executable to evaluate the captured workload's budget
with a fresh execution. Preserve its separate exit status and log: a nonzero
configuration/entitlement error is not structural red evidence. Do not relink or
re-sign between the two executions when claiming the same artifact.

## Signed checkpoint (2026-09-20)

Both native ARM64 Docker libc variants passed at scales 1, 8, 32 and 128. Signed
capture passed all semantic assertions at those scales and observed respectively
1, 8, 32 and 128 preparatory host position queries. The same signed executable's
strict budget test exited 101 with `ScalingViolation` at scale 1: actual 1,
maximum 0. This is an executed performance-contract failure, not a missing runner.
The unentitled negative control passed; both scoped cleanup checks found zero
remaining guests. The original inotify09 timing and broader promotion gates
remain unqualified.

The checkpoint used source HEAD `dd43066bef70d92f85a8ba99235ad31124b18452` plus the
working-tree source digest
`84d78973185a6f4ed3a68e3de01124db6e1c7d98309d7de72edd46cc9725aade`, including the
pre-existing runtime changes. The signed executable SHA-256 was
`d9da51ce575623c1b23b923b693d3325ca3764a2349f5f4ac56eebb4a516b7fa`, unchanged
across capture and budget evaluation. Exact CDHash, LC_UUID, entitlement and DOF
presence are in `target/investigations/write-seek-bindings/signed-artifacts.jsonl`;
`signed-observations.json`, `signed-budget.log`, `signed-budget.exit`, and
`budget-cleanup.log` retain the results. These target artifacts are local receipts,
not committed coverage attestations.

Contract tests (30), investigation tests (13), and the output-parser unit test
passed. Inventory/strategy checks, formatting, and focused tooling clippy passed.
Embed clippy with warnings denied remains blocked by the pre-existing unused
`sought_past_eof` field and methods; no warning suppression was added. Independent
static review of the binding changes found no blocking issues.
