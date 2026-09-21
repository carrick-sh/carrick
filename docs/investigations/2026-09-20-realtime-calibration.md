# Realtime calibration across sibling exec

Contract: `kernel.time.realtime-calibration`.

The full-run row `ltp-clock_gettime04`, `conf-2171-c82`, reported five passes
and one failure: CLOCK_REALTIME moved backwards by 1 ns on variant 1, the raw
syscall after a libc/vDSO read. The cached Docker row passed all six clocks.
The older blessed baseline only recorded broken setup on both sides; it does
not establish prior executed parity.

The carrier's syscall realtime clock reads `REALTIME_OFF_NS`, while each guest
address space retains its own vvar copy. `populate_vdso_data_page` previously
overwrote that shared offset on every exec. Two host clock samples yield slightly
different calibrations, so a sibling exec could strand existing vvar pages on a
different base. The fix publishes one immutable carrier-wide base and makes
every vvar stamper use the returned canonical value. Container clock adjustments
remain separate. Publication uses one compare-exchange, without retries or
walking existing address spaces.

## Attribution

The preserved pre-fix CLI came from source `9784dc289edcddc640ceab7386efe047917f6212`
plus the documented pre-existing filesystem WIP:

- SHA-256: `03d6545ce6e46988ef8e67bf1615b44b36d2f88740bfbeaf71811ed4809d1ad5`
- CDHash: `aef61a1683d22642ed13f702109d78ed11c2ca61`
- LC_UUID: `4FA13D27-5C19-3234-97B8-A744349EA53F`
- Entitlement and DOF receipt: `target/investigations/parity-20260920/signal-publication-fix-cli-artifact.json`.

One quiet LTP invocation and three subsequent invocations passed all six clocks.
A bounded workload of 100 sibling `/bin/true` execs alongside ten LTP invocations
reproduced CLOCK_REALTIME backwards by 42 ns on variant 2 (vDSO after syscall),
one failing invocation out of ten. No retry result replaces that failure.
All three Carrick run IDs were reaped with zero remaining scoped processes.

After the Carrick phase ended, identical native ARM64 Docker churn passed all
60 assertions. The oracle image is
`localhost:5050/ltp@sha256:bc75ded40c5827f2ec9e1891edc23b988beae3f428f5be2c8fd7e3ee52fee80b`.
Its LTP version is 20260529, and `clock_gettime04` executable SHA-256 is
`11f6edf3c9f5f08215658f8b0f128896114210045ed71e497f3e1cfcaededb6f`.
Both Docker containers used `--rm`; the oracle container census was empty.
Upstream semantic reference:
[LTP clock_gettime04](https://github.com/linux-test-project/ltp/blob/master/testcases/kernel/syscalls/clock_gettime/clock_gettime04.c).

## Verification

The deterministic host test uses an isolated calibration word, so it does not
mutate process-global clock state. Before the fix it failed at scale 1:
existing-vvar base 1000000, syscall base 999000. After the fix all 210
`carrick-mem` library tests pass, including scales 1, 8, 32 and 128.
The contract registry checker and focused formatting checks pass.

The new signed embed binding uses the exact image digest above and runs ten
LTP invocations alongside 1, 8, 32 and 128 sibling execs. It requires 60 TPASS
records at every scale, successful guest exit, and no TFAIL/TBROK/TCONF.
The signed run result and higher-layer promotion status are recorded below.

`scripts/test-signed.sh carrick-embed realtime_calibration_survives_sibling_exec`
passed the single selected test (240 TPASS assertions across all four scales)
and the unentitled negative control. Run ID
`clock-calibration-signed-20260920` and its `-cli` scope both cleaned up to zero.
The signed executable SHA-256 is
`09c37d5e0d407064b13a143bca37f94497cdb251664064dd93d3cf16653834c2`,
CDHash `676b9260215f5ceaf4938eff4da8f50b87aed4d0`.
The complete receipt is preserved as `signed-artifacts.jsonl` beside the
attribution logs below. The build includes concurrent filesystem WIP; it is
focused evidence for this contract, not an isolated whole-tree gate.
Broad probe, smoke, full-conformance and runtime-ratio promotion remain open
for the controller's integrated signed artifact.

Attribution and red/green logs are retained under
`target/investigations/parity-20260920/clock-calibration/`.
No runtime-ratio or full-conformance acceptance is inferred from these focused
semantic checks. The shared `target/release/carrick` was not rebuilt.
