# Public probe result on 863e81757

Source: `863e81757b066105ff9dd8696723983a20fdbc67`, clean for the run.
Command: `CARRICK_RUN_ID=el1-public-probes-20260926-863e81757 RUSTC_WRAPPER= just --no-deps conformance-probes`.
The command exits zero. This is a qualified public-gate result, not strict
conformance closure or completion of the EL1 memory checkpoint.

- 912 unique generic probe executions complete, covering both arm64 libc
  variants, with all three shard assertions passing.
- Four dedicated signed executables pass their selected cases. Negative
  entitlement controls pass in both signed stages.
- The CLI process-boundary contract passes.
- Retained arm64 musl: 33 PASS, zero DIFF.
- Retained arm64 GNU: 31 PASS, **two report-only DIFFs**.
- x86 probe lanes are explicitly skipped by this arm64 run; no x86 claim.
- Final scoped cleanup reports zero processes for the run and CLI child IDs.

## Open findings

GNU `ppollwaitset`, line 7: Carrick `wake_after_ms_bucket=lt100`, Linux `lt1`.
GNU `sigprofvdso`, line 7: Carrick `timer_pc_in_text=1`, Linux `0`.
Both exit zero with complete output. The retained harness classifies these as
report-only, so its zero exit status does not close these discrepancies.
Neither expected output nor probe source was changed. Controlled attribution
against native Linux and predecessor artifacts remains pending. Do not treat
these as proven regressions, harmless timing noise, or accepted gaps yet.

## Artifact scope

The CLI SHA-256 is
`ba157402cc698aff67322f2c1ef6a3670219832bd10d6007f7b9f748b5f77b97`.
It is unchanged after the gate and frozen at
`target/el1-completion/live-integrated/cli-frozen-863e81757`.
Its CDHash, LC_UUID, hypervisor entitlement and DOF are in the artifact JSON.
All 516 probe executables per libc were rehashed and matched the prior complete
build inventory before this run.

The separate signed receipts identify the executables used by each stage.
The public recipe re-signs all test executables between generic and dedicated
stages; the generic-stage receipt is preserved, but those exact earlier signed
files were not frozen before the dedicated re-sign. Final artifact-preserving
acceptance must retain each tested signed executable before the next stage
re-signs it. Do not equate a matching LC_UUID with matching signed identity.

Full CI on this revision is running separately at
`target/el1-completion/live-integrated/ci-863e81757.log`. Smoke/full promotion,
strict retained-probe closure, real EL1 first-touch service, and all later
migration checkpoints remain open. No workload speedup or 2x acceptance is claimed.

## Executable preservation follow-up

The four dedicated-stage executables remain byte-identical to their recorded
SHA-256 values and are now copied to
`target/el1-completion/live-integrated/dedicated-frozen-863e81757/`.
`dedicated-frozen-artifacts.json` records their exact paths and identities;
their existing receipt covers 32 passing test executions.

`freeze-signed-receipt.py RECEIPT DESTINATION` preserves completed signed
artifacts before another stage can re-sign them. It checks the full source
population before copying, verifies each copy and rechecks its source, then
saves the original receipt and capture manifest. Running it on the dedicated
receipt succeeded (four executables, 32 executions). Running it on the older
generic receipt failed with a source-artifact hash mismatch before creating
the destination. This confirms that the generic-stage artifact gap remains
open; later binaries cannot repair that evidence. On the next promotion, run
the capture after each signed stage and before starting the next signer.

The unentitled negative control is temporary and removed by the runner; this
capture preserves the entitled executables and the negative-control receipt,
not the removed negative executable. It adds no new guest execution claims.
