# Task 4 preparatory implementation report

## Status

`DONE_WITH_CONCERNS`

The discovery tooling, dedicated-scenario closure wiring, Node producer image,
signed Carrick artifact, and frozen 2,127-suite scope are prepared. The broad
2,127-suite discovery, complete probe runtime discovery, generated live ledger,
and any resulting mechanism-cluster plans remain coordinator-owned and have not
been run here.

## Red-first evidence

The report and dedicated-scenario Python tests were added before their production
scripts. The first closure test run failed because both modules were absent:

```text
FileNotFoundError: .../scripts/conformance/closure-report.py
FileNotFoundError: .../scripts/conformance/closure-probe-scenarios.py
Ran 6 tests; FAILED (errors=2)
```

The arm64 libc artifact selector test was added before its Rust interface:

```text
error[E0425]: cannot find function `dedicated_probe_target` in this scope
error: could not compile `carrick-cli` (test "conformance") due to 6 previous errors
```

Review then found that the sidecar selector had initially landed in a neighboring
Compose smoke. That unrelated edit was reverted, a sidecar-specific test was
added first, and the test failed on the missing correct interface:

```text
error[E0425]: cannot find function `dedicated_scenario_probe_target` in this scope
error: could not compile `carrick-cli` (test "serve") due to 5 previous errors
```

Finally, a subprocess-output test proved that an oracle-unavailable scenario
could return green while printing `NOTE`. It failed before the fail-closed guard:

```text
FAIL: test_runner_rejects_an_oracle_unavailable_note_even_when_cargo_is_green
AssertionError: ScenarioError not raised
```

Each red was caused by the missing production behavior rather than fixture or
syntax failure.

## Report validator

`scripts/conformance/closure-report.py` now:

- requires exactly 2,127 result rows whose names equal the frozen 2,127 unique
  suite names, rejecting missing, duplicate, and unexpected rows;
- partitions non-green discovery rows into semantic gaps, infrastructure
  failures, and unexercised assertions;
- separately records valid, completing `>=10x` pathological rows;
- validates the probe log against 409 generic plus 20 dedicated conformance
  sources under both arm64 libc sets; and
- renders the live ledger with source, signed-binary, manifest, image, raw-path,
  ratio, and mechanism-cluster fields once the coordinator supplies complete raw
  artifacts.

The live `docs/conformance-closure-ledger.md` is intentionally not fabricated
from fixtures. It remains an output of the pending complete discovery.

## Dedicated scenario closure denominator

Task 3's inventory has 20 dedicated **source rows** grouped behind 14 existing
scenario test functions:

- 13 functions in `crates/carrick-cli/tests/conformance.rs`;
- one ignored, explicitly selected function in
  `crates/carrick-cli/tests/serve.rs`.

`scripts/conformance/closure-probe-scenarios.py` derives the source-to-runner
groups from the inventory, requires exactly 20 sources and 14 functions, and
runs every function once per libc. A function counts only when Cargo reports
exactly one executed passing test and the output contains neither a `SKIP` nor
an oracle-unavailable `NOTE`. It emits one postcondition row for every inventory
source covered by the passing grouped scenario.

The exact denominator is:

```text
409 generic sources x 2 arm64 libcs = 818 rows
20 dedicated sources x 2 arm64 libcs = 40 rows
14 dedicated functions x 2 arm64 libcs = 28 function invocations
429 conformance sources x 2 arm64 libcs = 858 total gating rows
```

Every dedicated scenario consumes the selected
`aarch64-unknown-linux-{musl,gnu}` artifacts. The shared-network-namespace
scenario also selects both libc variants for the two additional bridge-compose
probe binaries it consumes as fixtures. The strict build denominator remains
430 binaries per libc because it also builds the `probeinit` helper.

`just conformance-probes-closure` now runs the existing 409-probe generic gate
and then the 20-source dedicated-scenario closure. The runtime recipe itself was
not run in this preparatory task.

## Node image and frozen artifact identity

The requested producer command completed without running conformance:

```text
scripts/nodejs-conformance-image.sh --build --push --metadata
```

Metadata:

```json
{"node24_ref":"v24.16.0","node26_ref":"v26.2.0","libuv_ref":"v1.52.1","image":"localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0"}
```

The published identity changed as required:

```text
old: sha256:50d22d4ee6776c57f6ad06ecc82e8219a9e5026e327aebab5847e17f61d46cbd
new: sha256:1ed49af83bd30401e1b275957b99a1c28f6c582ab3d987997afb5888fa302718
```

`just build` rebuilt and signed Carrick. The final frozen identity is:

```text
source_head: d4526fed56bfb34aed22316a65a942f33f3d8655
binary_sha256: 21e7d11449c23f6c6a1d254232101ae82294c4c7563f216b0d1c695924a6d0e1
suite_count: 2127
node_registry_digest: sha256:1ed49af83bd30401e1b275957b99a1c28f6c582ab3d987997afb5888fa302718
```

The signed binary has `com.apple.security.hypervisor` and `__dof_carrick`.
After the scope commit, the clean-tree live identity check passed:

```text
python3 scripts/conformance/closure-scope.py check scripts/conformance/closure-scope.json
closure scope checked: 2127 suites
```

## Green verification

Fresh focused verification after the final implementation changes:

```text
cargo test -p carrick-conformance
138 passed; 0 failed

python3 docker/nodejs-conformance/tests/test_normalize_tap.py
Ran 3 tests; OK

python3 -m unittest discover -s scripts/tests -p 'test_*closure*.py'
Ran 11 tests; OK

python3 scripts/tests/test_probe_inventory.py
Ran 3 tests; OK

cargo test -p carrick-cli --test conformance closure_ -- --nocapture
4 passed; 0 failed

cargo test -p carrick-cli --test serve \
  closure_sidecar_scenario_selects_both_arm64_libc_artifact_sets \
  -- --exact --nocapture
1 passed; 0 failed

python3 scripts/conformance/closure-probe-scenarios.py --check
dedicated closure plan: 20 sources, 14 runners

cargo clippy -p carrick-cli --test conformance --test serve -- -D warnings
exit 0

cargo fmt --check
exit 0

python3 -m py_compile scripts/conformance/closure-report.py \
  scripts/conformance/closure-probe-scenarios.py \
  scripts/tests/test_closure_report.py \
  scripts/tests/test_closure_probe_scenarios.py
exit 0

git diff --check
exit 0
```

The brief's literal `scripts/conformance/run-full.sh --tier full --dry-run`
fails because the wrapper already injects `--tier "$TIER"`, so Clap sees a
duplicate `--tier`. The supported equivalent passed:

```text
TIER=full scripts/conformance/run-full.sh --dry-run >/dev/null
exit 0
```

No guest or Docker oracle case was executed by either dry-run attempt.

## Commits

- `d4526fed56bfb34aed22316a65a942f33f3d8655`
  `test(conformance): prepare complete closure discovery`
- `ae6457a7e8e6481a06586ca0301a51e0cb05ce84`
  `test(conformance): refreeze closure artifact identity`

## Coordinator-owned measurements still pending

The following commands remain deliberately unrun:

```bash
TIER=full scripts/conformance/run-full.sh \
  --closure --lane hvf --force --refresh-oracle \
  --flake-retries 0 \
  --jsonl target/conformance/closure-initial/results.jsonl

mkdir -p target/conformance/closure-initial
set -o pipefail
just conformance-probes-closure 2>&1 \
  | tee target/conformance/closure-initial/probes.log

python3 scripts/conformance/closure-report.py \
  --scope scripts/conformance/closure-scope.json \
  --results target/conformance/closure-initial/results.jsonl \
  --probe-log target/conformance/closure-initial/probes.log \
  --output docs/conformance-closure-ledger.md
```

Concern: the first two are the authoritative broad runtime measurements and
must remain serialized and coordinator-owned. Until they produce 2,127 suite
rows and 858 probe rows, there is no honest live backlog or mechanism-cluster
ranking to report.
