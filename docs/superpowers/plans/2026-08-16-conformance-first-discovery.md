# Conformance-First Honest Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the minimum changes required to expose Carrick's real macOS/HVF arm64 conformance failures, immediately run the complete 2,127-suite plus arm64 musl/GNU probe discovery, and turn the result into the runtime-fix backlog.

**Architecture:** Add a narrow `--closure` path alongside the existing regression gate. Closure mode uses assertion identities, ignores all baseline/gap excuses, rejects every non-passing or missing result, and machine-checks the selected inventory. Avoid building a generalized certification framework now; record simple source/binary/image/result hashes for reproducibility, then move directly into reducers, tracing, and Carrick fixes.

**Tech Stack:** Rust 2024, `clap`, `serde`, `regex`, `sha2`, Python 3, signed macOS/HVF Carrick, native-arm64 Docker oracle, current conformance/probe harnesses.

## Global Constraints

- Scope is the canonical macOS/HVF arm64 HVPatch lane only.
- Full suite denominator is exactly 2,127 current manifest rows: 438 CPython, 194 Go, 3 Node, and 1,492 LTP.
- Closure mode never accepts `known_gaps`, baseline-pair excuses, `NEW`, shared failures, `TBROK`, `TCONF`, skips, report-only results, empty output, crashes, timeouts, oracle failures, retries, missing rows, or missing probe binaries/oracles.
- Existing regression mode and its cache/baseline remain usable.
- Carrick and Docker phases remain serialized. Cleanup is always scoped by run ID.
- Use TDD red-first for harness contracts and every later Carrick reducer.
- Prefer `carrick trace`/DTrace and `carrick debug lldb-run`/cores to log lines.
- Harness work not required to make the discovery honest is deferred until final certification.
- Preserve unrelated dirt and commit each task narrowly.

---

### Task 1: Minimal no-excuse closure mode

**Files:**
- Create: `crates/carrick-conformance/src/closure.rs`
- Modify: `crates/carrick-conformance/src/main.rs`
- Modify: `crates/carrick-conformance/src/lane.rs`
- Modify: `crates/carrick-conformance/src/verdict.rs`
- Modify: `crates/carrick-conformance/src/matrix.rs`

**Interfaces:**
- Produces: `ClosurePolicy::validate_args`, `classify_closure`, `validate_closure_reports`, and `Verdict::Incomplete`.
- Consumed by: the full discovery in Task 4.

- [ ] **Step 1: Write red invocation-policy tests**

```rust
#[test]
fn closure_requires_the_complete_hvf_run() {
    let mut args = ArgsFixture::closure();
    args.tier = "smoke".into();
    args.ecosystem = vec!["ltp".into()];
    args.flake_retries = 1;
    args.force = false;
    let errors = ClosurePolicy::validate_args(&args).unwrap_err();
    for expected in ["full tier", "filters", "flake retries", "--force"] {
        assert!(errors.iter().any(|error| error.contains(expected)), "{expected}");
    }
}

#[test]
fn unknown_lane_does_not_fall_back_to_hvf() {
    assert!(lane_from_args("bogus", "carrick", "host.lima.internal", 2.0, 1.0).is_err());
    assert!(lane_from_args("hvpatch", "carrick", "host.lima.internal", 2.0, 1.0).is_err());
}
```

- [ ] **Step 2: Write red closure-classification tests**

```rust
#[test]
fn closure_rejects_shared_failure_and_ignores_excuses() {
    let suite = suite_with_known_gap("assertion#1");
    let carrick = result(&[("assertion#1", Outcome::Broken)], SuiteOutcome::Failure);
    let docker = result(&[("assertion#1", Outcome::Broken)], SuiteOutcome::Failure);
    let got = classify_closure(&suite, &carrick, false, &docker);
    assert_eq!(got.verdict, Verdict::Incomplete);
    assert!(got.gating);
    assert!(got.known_diffs.is_empty());
}

#[test]
fn closure_accepts_only_nonempty_identical_all_ok_results() {
    let side = result(&[("assertion#1", Outcome::Ok)], SuiteOutcome::Success);
    assert!(!classify_closure(&suite(), &side, false, &side).gating);
    for outcome in [Outcome::Fail, Outcome::Broken, Outcome::Conf, Outcome::Skipped, Outcome::Xfail, Outcome::Uxsuccess, Outcome::Other] {
        let side = result(&[("assertion#1", outcome)], SuiteOutcome::Failure);
        assert!(classify_closure(&suite(), &side, false, &side).gating);
    }
}

#[test]
fn closure_report_inventory_must_equal_manifest() {
    let selected = vec![suite_named("a"), suite_named("b")];
    let reports = vec![report_named("a", Verdict::Match)];
    let error = validate_closure_reports(&selected, &reports).unwrap_err();
    assert!(error.to_string().contains("missing: b"));
}
```

- [ ] **Step 3: Run the focused tests and confirm red**

Run: `cargo test -p carrick-conformance closure::tests:: -- --nocapture`

Run: `cargo test -p carrick-conformance verdict::tests::closure_ -- --nocapture`

Run: `cargo test -p carrick-conformance lane::tests::unknown_lane -- --nocapture`

Expected: compile failures for the new closure interfaces and a failing unknown-lane compatibility test.

- [ ] **Step 4: Implement `--closure` without changing regression behavior**

Add `#[arg(long)] closure: bool` to `Args`. Closure requires `--lane hvf`, `--tier full`, `--force`, no suite/ecosystem filters, no retries, no allow-hang/bless/bless-from/seed-oracle, and no `--no-image-refresh`. Change `lane_from_args` to return `Result<Lane, String>` and enumerate accepted spellings explicitly.

```rust
pub fn classify_closure(
    suite: &Suite,
    carrick: &SuiteResult,
    carrick_timed_out: bool,
    docker: &SuiteResult,
) -> Classification {
    let all_ok = |side: &SuiteResult| {
        side.result == SuiteOutcome::Success
            && !side.ids.is_empty()
            && side.ids.values().all(|outcome| *outcome == Outcome::Ok)
    };
    if !carrick_timed_out && all_ok(carrick) && all_ok(docker) && carrick.ids == docker.ids
        && carrick.totals == docker.totals
    {
        return Classification::exact_match(carrick, docker);
    }
    Classification::incomplete_or_diff(carrick, docker)
}
```

Do not load or consult `Baseline` in this branch. `ORACLE_FAIL`, crash, timeout, empty result, a first observation, an exact shared non-pass, or any identity/outcome/count mismatch gates. After writing results, call `validate_closure_reports` and exit nonzero unless names exactly equal `selected` and every report is `MATCH`.

- [ ] **Step 5: Run all host tests and commit**

Run: `cargo test -p carrick-conformance`

```bash
git add crates/carrick-conformance/src/closure.rs crates/carrick-conformance/src/main.rs crates/carrick-conformance/src/lane.rs crates/carrick-conformance/src/verdict.rs crates/carrick-conformance/src/matrix.rs
git commit -m "feat(conformance): add a minimal no-excuse closure mode"
```

---

### Task 2: Make framework output assertion-exact enough for discovery

**Files:**
- Modify: `crates/carrick-conformance/Cargo.toml`
- Modify: `crates/carrick-conformance/src/parsers/mod.rs`
- Modify: `crates/carrick-conformance/src/parsers/ltp.rs`
- Modify: `crates/carrick-conformance/src/parsers/tap.rs`
- Modify: `crates/carrick-conformance/src/parsers/shell.rs`
- Modify: `crates/carrick-conformance/src/parsers/gotest.rs`
- Modify: `crates/carrick-conformance/src/parsers/regrtest.rs`
- Create: `docker/nodejs-conformance/normalize-tap.py`
- Create: `docker/nodejs-conformance/tests/test_normalize_tap.py`
- Modify: `docker/nodejs-conformance/nodejs-conformance`

**Interfaces:**
- Produces: `ParseMode::{Regression, Closure}`, `AssertionCollector`, and `parse_for_mode`.
- Consumed by: Task 1's `build_report` closure branch.

- [ ] **Step 1: Add the parser-mode and duplicate-occurrence contract**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseMode { Regression, Closure }

#[derive(Default)]
pub(crate) struct AssertionCollector {
    ids: BTreeMap<String, Outcome>,
    occurrences: BTreeMap<String, usize>,
}

impl AssertionCollector {
    pub fn push(&mut self, base: String, outcome: Outcome) {
        let occurrence = self.occurrences.entry(base.clone()).or_default();
        *occurrence += 1;
        self.ids.insert(format!("{base}#{}", *occurrence), outcome);
    }
}
```

Keep `parse(kind, raw)` as the regression wrapper; `parse_for_mode` selects closure variants.

- [ ] **Step 2: Write red LTP identity/count tests**

```rust
#[test]
fn closure_distinguishes_equal_counts_with_different_assertions() {
    let c = closure("a.c:10: TPASS: a\nb.c:20: TFAIL: b\nSummary:\npassed 1\nfailed 1\nbroken 0\nskipped 0\n");
    let d = closure("a.c:10: TFAIL: a\nb.c:20: TPASS: b\nSummary:\npassed 1\nfailed 1\nbroken 0\nskipped 0\n");
    assert_eq!(c.totals, d.totals);
    assert_ne!(c.ids, d.ids);
    assert_eq!(c.ids["ltp:a.c:10#1"], Outcome::Ok);
}

#[test]
fn closure_preserves_repeated_ltp_assertions() {
    let result = closure("loop.c:42: TPASS: iteration\nloop.c:42: TPASS: iteration\n");
    assert_eq!(result.ids.len(), 2);
    assert!(result.ids.contains_key("ltp:loop.c:42#2"));
}

#[test]
fn closure_rejects_summary_only_tbrok_tconf_and_count_mismatch() {
    for text in [
        "Summary:\npassed 0\nfailed 0\nbroken 1\nskipped 0\n",
        "Summary:\npassed 0\nfailed 0\nbroken 0\nskipped 1\n",
        "a.c:10: TPASS: a\nSummary:\npassed 2\nfailed 0\nbroken 0\nskipped 0\n",
    ] {
        assert_ne!(closure(text).result, SuiteOutcome::Success);
    }
}
```

- [ ] **Step 3: Write red TAP, shell, Go, and CPython exactness tests**

```rust
#[test]
fn closure_tap_requires_plan_and_assertions() {
    let result = TapParser.parse_closure(&raw(0, "TAP version 13\n1..2\nok 1 - alpha\nnot ok 2 - beta\n"));
    assert_eq!(result.ids["tap:1:alpha#1"], Outcome::Ok);
    assert_eq!(result.ids["tap:2:beta#1"], Outcome::Fail);
    assert_ne!(TapParser.parse_closure(&raw(0, "ok 1 - no-plan\n")).result, SuiteOutcome::Success);
}

#[test]
fn closure_shell_body_is_part_of_the_result() {
    let a = ShellParser.parse_closure(&raw_parts(0, "BUILD_OK\n", ""));
    let b = ShellParser.parse_closure(&raw_parts(0, "WRONG\n", ""));
    assert_ne!(a.ids, b.ids);
}

#[test]
fn closure_keeps_go_and_python_duplicate_subtests() {
    assert_eq!(closure_go(pointer_duplicate_fixture()).ids.len(), 2);
    let py = closure_python("test_a (m.C.test_a) [1] ... ok\ntest_a (m.C.test_a) [2] ... FAIL\nResult: FAILURE\n");
    assert!(py.ids.contains_key("py:m.C.test_a[1]#1"));
    assert!(py.ids.contains_key("py:m.C.test_a[2]#1"));
}
```

- [ ] **Step 4: Add red Node wrapper normalization tests**

```python
def test_preserves_existing_tap_without_temp_path(self):
    got = normalize("node-core", 0, "TAP version 13\n1..1\nok 1 - test-a\n")
    self.assertEqual(got, "TAP version 13\n1..1\nok 1 - test-a\n")
    self.assertNotIn("/tmp/", got)

def test_plain_smoke_is_one_tap_assertion(self):
    self.assertEqual(normalize("v8-smoke", 0, "v8-smoke ok\n"), "TAP version 13\n1..1\nok 1 - v8-smoke\n")
```

- [ ] **Step 5: Run and confirm red**

Run: `cargo test -p carrick-conformance parsers:: -- --nocapture`

Run: `python3 docker/nodejs-conformance/tests/test_normalize_tap.py`

Expected: closure tests fail on synthetic summaries/suite IDs, duplicate collapsing, and missing normalizer.

- [ ] **Step 6: Implement only the observed false-green parsing fixes**

LTP closure mode parses modern `source.c:line: TPASS|TFAIL|TBROK|TCONF`, old API `binary case token :`, and legacy numbered `PASSED|FAILED` lines into occurrence-preserving IDs. It reconciles a present summary against observed counts. Summary-only, TINFO-only, count-mismatched, or assertion-free output is incomplete and therefore gating.

TAP closure mode requires a single `1..N` plan, unique in-range assertion numbers, exact plan/count agreement, and no bailout. Shell closure mode emits exact exit code plus SHA-256 of separately normalized stdout/stderr; add `sha2.workspace = true`. Go and CPython closure modes retain duplicate occurrences and CPython `[N]` subtest ordinals.

`normalize-tap.py` preserves valid existing TAP and wraps plain smoke output as one TAP assertion. `run_logged` passes its retained log through the normalizer, removes the temp file, and never prints the random path.

- [ ] **Step 7: Run tests and commit**

Run: `cargo test -p carrick-conformance`

Run: `python3 docker/nodejs-conformance/tests/test_normalize_tap.py`

```bash
git add crates/carrick-conformance/Cargo.toml crates/carrick-conformance/src/parsers docker/nodejs-conformance
git commit -m "feat(conformance): expose exact framework assertions"
```

---

### Task 3: Freeze a simple scope and make both arm64 probe sets fail closed

**Files:**
- Create: `scripts/conformance/closure-scope.py`
- Create: `scripts/conformance/closure-scope.json`
- Create: `scripts/tests/test_closure_scope.py`
- Create: `conformance-probes/probe-inventory.json`
- Create: `scripts/probe-inventory.py`
- Create: `scripts/tests/test_probe_inventory.py`
- Modify: `scripts/build-probes.sh`
- Modify: `crates/carrick-cli/tests/conformance.rs`
- Modify: `justfile`

**Interfaces:**
- Produces: `closure-scope.py freeze|check`, explicit probe source classes, `build-probes.sh --closure-arm64`, and `CARRICK_PROBE_MODE=closure`.
- Consumed by: Task 4 discovery commands.

- [ ] **Step 1: Add red scope tests**

```python
def test_scope_requires_exact_manifest_names_and_count(self):
    scope = freeze_scope(self.manifest, self.images)
    self.assertEqual(scope["suite_count"], 2127)
    self.assertEqual(len(scope["suite_names"]), 2127)
    with self.assertRaises(ScopeError):
        check_scope(scope, manifest_without_one_suite())

def test_scope_records_source_binary_manifest_and_image_identities(self):
    scope = freeze_scope(self.manifest, self.images)
    for key in ["source_head", "binary_sha256", "manifest_sha256", "images"]:
        self.assertIn(key, scope)
```

- [ ] **Step 2: Add red probe inventory/build/closure tests**

```python
def test_probe_inventory_partitions_all_455_sources(self):
    inventory = load_inventory()
    self.assertEqual(set(inventory), source_names())
    self.assertEqual(len(inventory), 455)

def test_missing_arm64_binary_is_a_closure_failure(self):
    with self.assertRaises(ProbeInventoryError):
        check_binaries(inventory(), target_dir_missing("kernelidentity"), "arm64-musl")
```

```rust
#[test]
fn closure_gates_arm64_musl_and_gnu_and_rejects_skips() {
    assert!(ARM64.probe_sets.iter().all(|set| closure_set_gates(&ARM64, set)));
    assert!(validate_closure_probe_inventory(&fixture_missing_binary()).is_err());
    assert!(validate_closure_probe_inventory(&fixture_unblessed()).is_err());
    assert!(validate_closure_probe_inventory(&fixture_skipped()).is_err());
}
```

- [ ] **Step 3: Run and confirm red**

Run: `python3 -m unittest discover -s scripts/tests -p 'test_*closure*.py'`

Run: `python3 scripts/tests/test_probe_inventory.py`

Run: `cargo test -p carrick-cli --test conformance closure_ -- --nocapture`

Expected: tests fail because scope/inventory scripts are absent and GNU is report-only.

- [ ] **Step 4: Implement the simple suite scope record**

The JSON contains schema, source HEAD, Carrick binary SHA-256, manifest SHA-256, sorted suite names/counts by ecosystem, declared image refs, and live Docker/registry digest strings. `check` fails on missing/malformed fields, dirty source, hash/name/count drift, or an unresolved image digest. Do not build a generalized receipt library.

- [ ] **Step 5: Implement the explicit probe partition**

Classify the exact 25 `perf_*` sources as `performance`, `probeinit` as `helper`, and every other source as `conformance`. Record `generic` or the existing dedicated scenario runner. Initial exclusions are empty. A source absent from the inventory or an inventory row absent from disk fails.

- [ ] **Step 6: Add strict `--closure-arm64` build behavior**

Clear only the two arm64 release directories, build musl and GNU, then require every inventory-selected arm64 conformance/helper binary and reject stale extra source-backed binaries. The command exits nonzero on compile failures; it never uses `--keep-going || true` as success. Fix current source portability errors narrowly until both expected sets exist.

- [ ] **Step 7: Make closure probe execution fail rather than skip**

In `CARRICK_PROBE_MODE=closure`, select only ARM64, require both libcs, set both gating, forbid filter/backend overrides, require Carrick/Docker/probe directories/binaries/oracles, and assert `GATE_SKIP_PROBES` contributes no selected conformance source. Preserve existing behavior outside closure mode.

- [ ] **Step 8: Add recipes, run checks, and commit**

```make
conformance-closure-scope:
    python3 scripts/conformance/closure-scope.py check scripts/conformance/closure-scope.json

conformance-probes-closure: build
    ./scripts/build-probes.sh --closure-arm64
    CARRICK_PROBE_MODE=closure CARRICK_PROBE_LANE=arm64 CARRICK_EXEC_BACKEND=hvpatch \
      cargo test -p carrick-cli --test conformance conformance_probes -- --exact --nocapture
```

Run: `python3 -m unittest discover -s scripts/tests -p 'test_*closure*.py'`

Run: `python3 scripts/tests/test_probe_inventory.py`

Run: `./scripts/build-probes.sh --closure-arm64`

Run: `cargo test -p carrick-cli --test conformance closure_ -- --nocapture`

```bash
git add scripts/conformance/closure-scope.py scripts/conformance/closure-scope.json scripts/tests/test_closure_scope.py conformance-probes/probe-inventory.json scripts/probe-inventory.py scripts/tests/test_probe_inventory.py scripts/build-probes.sh crates/carrick-cli/tests/conformance.rs justfile
git commit -m "test(conformance): freeze and gate the macOS proof surface"
```

---

### Task 4: Run the complete honest discovery immediately

**Files:**
- Create from run: `target/conformance/closure-initial/`
- Create: `scripts/conformance/closure-report.py`
- Create: `scripts/tests/test_closure_report.py`
- Create: `docs/conformance-closure-ledger.md`

**Interfaces:**
- Consumes: closure suite mode from Tasks 1-2 and frozen/probe scope from Task 3.
- Produces: machine-counted suite/probe backlog and the live correctness ledger.

- [ ] **Step 1: Add the report validator test before the long run**

```python
def test_report_requires_all_2127_unique_rows(self):
    with self.assertRaises(ReportError):
        summarize(scope_2127(), results_2126())
    with self.assertRaises(ReportError):
        summarize(scope_2127(), results_with_duplicate())

def test_report_separates_semantic_infrastructure_and_unexercised_rows(self):
    summary = summarize(scope(), fixture_results())
    self.assertEqual(summary["semantic_gaps"], ["ltp-futex"])
    self.assertEqual(summary["infrastructure_failures"], ["ltp-tracefs"])
    self.assertEqual(summary["unexercised"], ["ltp-cgroup"])
```

- [ ] **Step 2: Run host and signing gates**

Run: `cargo test -p carrick-conformance`

Run: `python3 docker/nodejs-conformance/tests/test_normalize_tap.py`

Run: `python3 -m unittest discover -s scripts/tests -p 'test_*closure*.py'`

Run: `python3 scripts/tests/test_probe_inventory.py`

Run: `just build`

Run: `scripts/conformance/run-full.sh --tier full --dry-run >/dev/null`

Run: `python3 scripts/conformance/closure-scope.py freeze scripts/conformance/closure-scope.json`

Expected: all tests pass, Carrick is signed, and the frozen scope records exactly 2,127 suites.

- [ ] **Step 3: Run the full suite discovery with a fresh oracle**

Run:

```bash
scripts/conformance/run-full.sh \
  --closure --lane hvf --tier full --force --refresh-oracle \
  --flake-retries 0 \
  --jsonl target/conformance/closure-initial/results.jsonl
```

Expected: 2,127 unique result rows. The command is expected to exit nonzero until Carrick is conformant; a complete red result is useful evidence, while a missing row is a harness failure to fix immediately.

- [ ] **Step 4: Run the arm64 musl/GNU probe discovery**

Run:

```bash
mkdir -p target/conformance/closure-initial
set -o pipefail
just conformance-probes-closure 2>&1 \
  | tee target/conformance/closure-initial/probes.log
```

Expected: every selected probe either passes or produces a real gating mismatch/error. No report-only, unblessed, missing, or skipped row is accepted.

- [ ] **Step 5: Generate the live ledger**

Run:

```bash
python3 scripts/conformance/closure-report.py \
  --scope scripts/conformance/closure-scope.json \
  --results target/conformance/closure-initial/results.jsonl \
  --probe-log target/conformance/closure-initial/probes.log \
  --output docs/conformance-closure-ledger.md
```

The ledger records exact source/binary/manifest/image identities, counts, every semantic gap, infrastructure failure, unexercised assertion, pathological valid `>=10x` row, raw artifact path, and a mechanism-cluster field. It is controller state and is updated after every cluster closes.

- [ ] **Step 6: Commit the discovery tooling and ledger**

```bash
git add scripts/conformance/closure-report.py scripts/tests/test_closure_report.py docs/conformance-closure-ledger.md scripts/conformance/closure-scope.json scripts/conformance/oracle-cache.jsonl
git commit -m "test(conformance): record the first honest macOS backlog"
```

## Verification mapping

- Honest invocation and zero excuses: Task 1.
- Assertion identity instead of aggregate counts/exit codes: Task 2.
- Frozen 2,127-suite scope and both arm64 probe sets: Task 3.
- Immediate full evidence and live backlog: Task 4.

This plan is mis-executed if receipt abstractions, baseline rendering, or generalized harness refactors delay the first full discovery after Tasks 1-3.

Once Task 4 writes the ledger, immediately create standing-approved follow-on
plans for the actual named mechanism clusters in that ledger. Rank timeout and
crash clusters first, then framework blockers hiding many assertions, then
semantic fan-out, valid completing `>=10x` pathology, and isolated assertions.
Each follow-on plan must name its concrete reducer, durable trace/core artifact,
owning source files, pre-fix red command, post-fix suite command, and commit
boundary. Broad Carrick/Docker measurements remain coordinator-owned and
serialized.
