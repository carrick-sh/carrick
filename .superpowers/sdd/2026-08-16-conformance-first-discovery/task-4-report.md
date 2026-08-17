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

## Review round 1/5

### Red-first evidence

The assertion-level/non-exclusive report tests failed against the preparatory
implementation because it returned suite names and selected one category by
precedence:

```text
FAIL: test_report_separates_semantic_infrastructure_unexercised_and_pathological_rows
Lists differ: ['ltp-futex'] != [{'suite': 'ltp-futex', 'assertion': 'futex.c:42#1', ...}]

FAIL: test_suite_can_contribute_semantic_and_unexercised_assertions
Lists differ: [] != ['mixed.c:10#1', 'mixed.c:20#1']
```

The complete-red probe-log tests failed because canonical red terminal rows
were not recognized and therefore appeared as 858 missing rows:

```text
ERROR: test_probe_log_retains_complete_red_terminal_rows
ReportError: probe log does not close both arm64 libc sets (rows=0, ...)
```

The dedicated continuation tests failed before terminal-result collection
existed:

```text
AttributeError: module 'closure_probe_scenarios' has no attribute 'TerminalRow'
TypeError: run_plan() got an unexpected keyword argument 'command_runner'
ScenarioError: scenario conformance_bridge_publish_tcp [musl] did not fully gate
```

The generic terminal-policy test also failed on the missing Rust mapping:

```text
error[E0425]: cannot find function `closure_probe_terminal_status` in this scope
error: could not compile `carrick-cli` (test "conformance") due to 5 previous errors
```

### Fixes

- Suite summarization is assertion-level and non-exclusive. Each semantic
  divergence records suite, assertion identity, Carrick outcome, and Docker
  outcome. Every `skipped`/`conf`/`absent` assertion is independently recorded
  as unexercised, so one assertion and one suite may appear in both sections.
  Infrastructure remains a suite-level category. Ledger tables now render the
  assertion identities rather than suite-only precedence.
- Generic closure output now emits one canonical terminal line per selected
  source/libc row: `CLOSURE_PROBE GENERIC PASS|FAIL|NOTE|ERROR ...`. Known-gap
  `XFAIL` and unexpected pass both lower to closure `FAIL`; closure no longer
  accepts a missing oracle as an excuse.
- Dedicated execution returns a terminal result instead of raising on the first
  red scenario. All 14 functions run under GNU and musl, exceptions and malformed
  Cargo results lower to `ERROR`, and each grouped source receives exactly one of
  40 canonical `CLOSURE_PROBE SCENARIO ...` rows. The script exits nonzero only
  after the complete 28-invocation matrix finishes.
- The `just conformance-probes-closure` shell captures generic and dedicated
  statuses independently, always runs the dedicated phase after a red generic
  phase, and exits nonzero only after both phases finish.
- The report parser requires exactly one canonical terminal row for all 858
  expected keys. Red rows count as complete evidence. Unknown, duplicate,
  malformed, extra, and standalone terminal states fail closed. A complete
  858-PASS log plus an extra canonical `FAIL`, `SKIP`, or `NOTE` is explicitly
  tested and rejected.
- Ledger rendering has explicit probe semantic-failure, infrastructure-failure,
  and unexercised sections. `NOTE`/oracle-unavailable is retained in both the
  infrastructure and unexercised views.

### Green verification

```text
python3 -m unittest discover -s scripts/tests -p 'test_*closure*.py'
Ran 16 tests; OK

cargo test -p carrick-cli --test conformance closure_ -- --nocapture
5 passed; 0 failed

cargo clippy -p carrick-cli --test conformance --test serve -- -D warnings
exit 0

cargo fmt --check
exit 0

python3 scripts/conformance/closure-probe-scenarios.py --check
dedicated closure plan: 20 sources, 14 runners

python3 -m py_compile scripts/conformance/closure-report.py \
  scripts/conformance/closure-probe-scenarios.py \
  scripts/tests/test_closure_report.py \
  scripts/tests/test_closure_probe_scenarios.py
exit 0

just --dry-run conformance-probes-closure
generic_status and dedicated_status are captured; both phases precede final exit

git diff --check
exit 0
```

The synthetic runner test made the first GNU scenario fail and proved all 28
function/libc calls still occurred, including the final musl function, producing
all 40 terminal source rows.

### Commit and remaining concern

- `9873d0af1b2de79ee8f09815ff5e2d88f0484147`
  `fix(conformance): retain complete red closure evidence`

No broad suite or probe measurement was run in this review. The coordinator
still owns the authoritative 2,127-suite and 858-probe runtime discoveries.

## Review round 2/5

### Red-first evidence

Exact synthetic raw forms were appended to an otherwise complete 858-PASS log.
Before the independent raw-state guards, each reviewer example was silently
accepted:

```text
FAIL: test_probe_log_rejects_raw_dedicated_skip_note_and_cargo_failure

raw_line='SKIP conformance_bridge_tcp_peer: target/release/carrick not built'
AssertionError: ReportError not raised

raw_line='NOTE conformance_bridge_publish_tcp: Docker oracle unavailable'
AssertionError: ReportError not raised

raw_line='test conformance_bridge_udp_peer ... FAILED'
AssertionError: ReportError not raised
```

Tightening the consumer exposed that the dedicated producer forwarded raw Cargo
failure lines before its canonical terminal rows. The producer regression test
failed red on that leak:

```text
FAIL: test_plan_prefixes_raw_cargo_failure_output_as_nonterminal_detail
AssertionError: '\ntest conformance_bridge_compose_pair ... FAILED\n' unexpectedly found
```

### Fixes

- `closure-report.py` now independently rejects raw dedicated
  `SKIP conformance_<runner>: ...`, `NOTE conformance_<runner>: ...`, including
  oracle-unavailable notes, and `test <dedicated-runner> ... FAILED` anywhere in
  the log. The runner name must be one of the inventory-derived dedicated
  scenario functions, avoiding broad matches on unrelated Cargo output.
- Existing raw generic `FAIL arm64:<libc>:<source>` and
  `ERROR arm64:<libc>:<source> ...` rejection is covered explicitly.
- Canonical `CLOSURE_PROBE ...` terminal lines and benign
  `test conformance_<runner> ... ok` Cargo noise remain accepted; a complete
  canonical 858-PASS fixture verifies no false positive.
- Dedicated raw stdout/stderr is retained under the non-terminal
  `CLOSURE_PROBE_DETAIL <libc>:<runner>:` prefix. Raw Cargo `FAILED`, scenario
  `SKIP`, and scenario `NOTE` strings therefore cannot leak as standalone
  states from the producer, while the canonical source/libc terminal rows and
  full diagnostics remain available.

### Green verification

```text
python3 -m unittest discover -s scripts/tests -p 'test_*closure*.py'
Ran 20 tests; OK

cargo test -p carrick-cli --test conformance closure_ -- --nocapture
5 passed; 0 failed

cargo clippy -p carrick-cli --test conformance --test serve -- -D warnings
exit 0

cargo fmt --check
exit 0

python3 scripts/conformance/closure-probe-scenarios.py --check
dedicated closure plan: 20 sources, 14 runners

git diff --check
exit 0
```

### Scope provenance refresh

This round changed only Python tooling and tests, so Carrick was not rebuilt.
After committing the code/tests cleanly, `closure-scope.json` was frozen from
that commit. Its diff changed only `source_head`:

```text
source_head: 1befe20cddcab86b80bfb9af3ae1f5f9479977e9
binary_sha256: 21e7d11449c23f6c6a1d254232101ae82294c4c7563f216b0d1c695924a6d0e1
node_registry_digest: sha256:1ed49af83bd30401e1b275957b99a1c28f6c582ab3d987997afb5888fa302718
suite_count: 2127
```

The following checks passed after the scope-data commit:

```text
git merge-base --is-ancestor "$source_head" HEAD
exit 0

git merge-base --is-ancestor \
  9873d0af1b2de79ee8f09815ff5e2d88f0484147 "$source_head"
exit 0

python3 scripts/conformance/closure-scope.py check \
  scripts/conformance/closure-scope.json
closure scope checked: 2127 suites
```

Thus the recorded source commit contains review round 1's complete-red code and
all round 2 raw-log hardening, and precedes only the scope-data/report commits.
The signed binary and Node image identities are unchanged and verified live.

### Commits and remaining concern

- `1befe20cddcab86b80bfb9af3ae1f5f9479977e9`
  `fix(conformance): reject raw closure probe states`
- `01ab27c4325ec911607efe66b67f0f22bcffa868`
  `test(conformance): advance closure tooling provenance`

No broad measurement was run. The coordinator still owns the authoritative
2,127-suite and 858-probe runtime discoveries.

## Runtime fix round 3/5

The coordinator completed the broad runtime discovery before this round. This
round used the observed result shape only; it did not run guests or Docker and
did not read, rewrite, stage, or commit the dirty refreshed oracle cache.

### Red-first evidence

A complete synthetic 2,127-row fixture included the real discovery shape:
`verdict=incomplete`, both side results `success`, all totals zero, and
`pairs={}`. Before the fix the focused test failed at the same guard as live
`cpython-abc`:

```text
ERROR: test_both_success_zero_assertion_suite_is_retained_as_unexercised
ReportError: result row 'cpython-zero' is non-match without an attributable assertion
```

### Minimal fix

`summarize` now recognizes only the exact both-success zero-assertion shape and
adds this suite-level synthetic assertion to the unexercised ledger:

```text
assertion: <no assertions>
carrick: absent
docker: absent
```

The row is not verified and cannot become a valid `>=10x` pathology even when
it carries a large timing ratio. Other empty-pairs non-match shapes remain
fail-closed: the same fixture with a nonzero Carrick assertion total is tested
and still raises `ReportError`.

### Green verification

```text
python3 -m unittest discover -s scripts/tests -p 'test_*closure*.py'
Ran 21 tests; OK

python3 -m py_compile scripts/conformance/closure-report.py \
  scripts/tests/test_closure_report.py
exit 0

cargo fmt --check
exit 0

git diff --check
exit 0
```

### Commit and retained external state

- `240d711bb02f7a2a3e54146e338a61b4f260beee`
  `fix(conformance): retain zero-assertion closure rows`

The pre-existing modified `scripts/conformance/oracle-cache.jsonl` remains
unstaged and uncommitted exactly as received. No target artifact was touched.

## Runtime fix round 4/5

This round addressed the real `ltp-msgstress01` and `ltp-shmget04` result shape
without running guests or Docker and without touching the dirty oracle cache or
target artifacts.

### Red-first evidence

The complete 2,127-row fixture reproduced the exact observation:

- verdict `incomplete`;
- Carrick suite result `failure`;
- Docker suite result `success`;
- equal nonzero totals;
- every recorded assertion pair `ok/ok`.

Before the fix, the focused test reached the same unattributable guard as the
ledger preview:

```text
ERROR: test_post_assertion_process_failure_is_infrastructure_not_assertion_semantics
ReportError: result row 'ltp-post-assertion' is non-match without an attributable assertion
```

### Minimal fix

`summarize` now identifies a post-assertion/process failure only when all of the
following hold:

- verdict is `incomplete`;
- Carrick is `failure` and Docker is `success`;
- both sides have identical totals with `n > 0`;
- assertion pairs are nonempty and every pair is `ok/ok`.

That exact shape is retained as a suite-level infrastructure failure and cannot
enter verified or pathological output, even with a `>=10x` ratio. The test then
changes the pair to `fail/ok` and proves the row remains an assertion-level
semantic gap and is not indiscriminately reclassified as infrastructure.

### Green verification

```text
python3 -m unittest discover -s scripts/tests -p 'test_*closure*.py'
Ran 22 tests; OK

python3 -m py_compile scripts/conformance/closure-report.py \
  scripts/tests/test_closure_report.py
exit 0

cargo fmt --check
exit 0

git diff --check
exit 0
```

### Commit and retained external state

- `e2cdd9973021185321ba537bfdf7326f1ff87c7f`
  `fix(conformance): retain post-assertion failures`

The pre-existing modified `scripts/conformance/oracle-cache.jsonl` remains the
sole unstaged path. No broad measurement or target-artifact operation occurred.

## Runtime fix round 5/5

The final reviewer round tightened the post-assertion/process-failure exception
without running guests or Docker and without touching target artifacts or the
dirty oracle cache.

### Red-first evidence

Three exact near-miss fixtures were added before changing production. The
previous round's condition incorrectly accepted all three as infrastructure:

```text
FAIL: test_post_assertion_exception_rejects_inconsistent_totals_and_cardinality

case='partial-pass-total'
n=2 passed=1 pairs=1
AssertionError: ReportError not raised

case='failed-total-with-ok-pair'
n=1 passed=0 failed=1 pairs=1
AssertionError: ReportError not raised

case='assertion-cardinality-mismatch'
n=3 passed=3 pairs=1
AssertionError: ReportError not raised
```

### Exact consistency fix

The suite-level post-assertion exception now requires all of the following:

- verdict `incomplete`;
- Carrick `failure` and Docker `success`;
- both totals nonzero and identical;
- for both sides, `n == passed` and `failed == broken == skipped == 0`;
- nonempty assertion pairs with `len(pairs) == n` on both sides;
- every pair exactly `ok/ok`.

The existing two-assertion all-pass fixture representing the real
`ltp-msgstress01`/`ltp-shmget04` shape remains an infrastructure failure. The
three inconsistent shapes now continue to the unattributable guard and raise,
and the `fail/ok` fixture remains assertion-level semantic evidence.

### Green verification

```text
python3 -m unittest discover -s scripts/tests -p 'test_*closure*.py'
Ran 23 tests; OK

python3 -m py_compile scripts/conformance/closure-report.py \
  scripts/tests/test_closure_report.py
exit 0

cargo fmt --check
exit 0

git diff --check
exit 0
```

### Commit and retained external state

- `70d1684b7434977d30cbe5ab9746e6e84439c4a6`
  `fix(conformance): tighten post-assertion evidence`

The refreshed `scripts/conformance/oracle-cache.jsonl` remains the sole dirty,
unstaged path. No runtime or target-artifact command ran.

## Coordinator-owned authoritative discovery

The final measurement used the frozen signed Carrick artifact directly, without
another `just build`, because the signing wrapper relinks/resigns its release
output and therefore changes the artifact hash. Carrick and Docker ran in
strictly serialized phases with `--refresh-oracle`, no retries, no baseline, and
no filter.

- Suites: 2,127 unique rows (1,197 MATCH, 930 INCOMPLETE).
- Exact assertions: 8,317 semantic gaps, 11,278 unexercised rows, 609 suites
  with infrastructure failure evidence.
- Valid pathologies: 6 completing MATCH suites at >=10x.
- Liveness: 10 blocked timeouts.
- Probes: 858/858 arm64 musl/GNU rows (842 PASS, 16 FAIL, zero skip/note/error).
- Dedicated scenarios: all 28 invocations ran and emitted all 40 source/libc
  rows; four rows failed.

Final receipt:

- Scope source: `6882ea1285cb677577dbac3bd34f8618adaf28d2`
- Signed SHA-256: `b88db5ee72c67d2d16d52521a152aaf055a5f5e17af271c155a591e4d662a1ad`
- CDHash: `f33b276f9101995dee613c87119d22c80d02ca6a`
- LC_UUID: `8D032E4F-FBC0-363A-BC40-C7BF86E116EA`
- Hypervisor entitlement: present/true
- `__dof_carrick`: present (one load-command match)
- Results SHA-256: `23dbc6c058304905c10f8a2cc5981220ff5b121ca04b3e65cf0571cf509c427c`
- Probe-log SHA-256: `b02377e3badabada9976a1fea87590d2a00621960e371c738635561c32b24904`
- Suite-log SHA-256: `7685bdf984a234767d49f45918c05101025a689817721dc8975de1b115d6a7bc`
- Ledger SHA-256: `cd77df60c8761c0f96db9f31eff8cabb18f7a57d7e043ea33be536eb7ea07fa7`
- Cleanup: zero live `carrick`/`carrick:conf-*` processes and zero `conf-*`
  containers.

Committed controller state:

- `83dcfe480` records the final fresh oracle.
- `6882ea12` records the first three runtime-cluster plans and explicit mapping.
- `fbba9b09` binds clustered-ledger provenance.
- `9fe10d9f` records the regenerated clustered ledger.
