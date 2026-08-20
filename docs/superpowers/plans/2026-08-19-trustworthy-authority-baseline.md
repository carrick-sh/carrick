# Trustworthy Authority Baseline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Carrick's current syscall-authority boundary explicit,
drift-gated, and honestly measurable, then freeze a fresh signed Phase 0
conformance baseline without claiming the broader campaign is complete.

**Architecture:** Keep Phase 0 structural and observational.
`carrick-abi` spells authority on every syscall row. A deterministic offline
escape-hatch lint and a compiler-resolved, independently receipted review
inventory drift-gate the three executed macOS product profiles. Human review
supplies semantic classification; six non-local profiles remain pending, and
173 locally forbidden rows remain debt. The existing fail-closed closure
harness will measure the exact current tree and create evidence input for the
Phase 1 typed-capability and lifecycle plans.

**Tech Stack:** Rust 2024, Bash, Python 3 `unittest`, Semgrep 1.166+, Just,
Docker Desktop, Hypervisor.framework, Carrick's closure harness, arm64
musl/GNU conformance probes.

**Spec:**
`docs/superpowers/specs/2026-08-19-authority-enforced-kernel-closure-design.md`

## Global Constraints

- Canonical completion lane: macOS, Apple Silicon, HVF/HVPatch, Linux arm64.
- Build guest-running binaries only through `just build` or
  `scripts/build-signed.sh`; a plain Cargo build is compile-only.
- Keep Apple `ld64`; the signed artifact must retain the hypervisor entitlement
  and `__dof_carrick`.
- Carrick and Docker oracle workloads never overlap.
- Use `CARRICK_RUN_ID` and `scripts/sudo/kill.sh <run-id>` for scoped cleanup;
  never use an unscoped `pkill`.
- Preserve the frozen 2,127-suite closure surface and every applicable arm64
  musl/GNU probe. Do not bless, waive, retry, allow-hang, or weaken closure.
- A Guest-authority operation may use only declared guest-memory or carrier
  substrate mechanics; it may not use semantic host process, identity,
  credential, path, namespace, or signal authority.
- Use red-first tests for every new gate. Keep existing behavior unchanged while
  converting implicit authority metadata to explicit declarations.
- Preserve unrelated worktree state. Use narrow commits and durable receipts.
- Phase 0 establishes truth and prevents drift. It does not satisfy the final
  security, conformance, or performance goal.

---

## File Map

### New files

- `scripts/lint-domains.sh` — deterministic offline Semgrep launcher with an
  explicit CA bundle and writable log.
- `scripts/tests/test_lint_domains.py` — launcher contracts using a fake
  Semgrep binary.
- `scripts/migrate/check-host-authority-transitions.py` — execute the pinned
  compiler matrix, normalize diagnostics, and validate checked receipts and
  reviews without parsing Rust source.
- `scripts/migrate/host-authority-transition-inventory.json` — checked
  compiler-resolved callsite inventory with structured evidence and human
  classification.
- `scripts/migrate/host-authority-macos-capture.json` — independent binding of
  the local compiler diagnostics and exact profile memberships.
- `.semgrep/host-authority-escape-hatches.yml` — narrow deny rules for raw
  syscall, dynamic lookup, assembly, and watched local FFI declarations.
- `scripts/tests/test_host_authority_transitions.py` — compiler receipt,
  inventory drift, classification, and matrix contracts.
- `scripts/tests/test_host_authority_escape_hatches.py` — real temporary-file
  Semgrep contracts, including false-positive and exact-boundary cases.
- `docs/perf-results/2026-08-19-authority-phase0/README.md` — exact signed
  checkpoint, authority counts, current closure result, and explicit blockers.

### Modified files

- `justfile:89-110` — call the deterministic launcher and the real read-only
  compiler census `--check`.
- `crates/carrick-abi/src/syscall.rs:47-168,268-654` — pass an explicit
  `Authority` to every `syscall(...)` row and remove the catch-all classifier.
- `crates/carrick-runtime/tests/integration/syscall_table.rs:260-320` — prove
  every row spells its authority and preserve representative partition checks.
- `docs/host-facility-boundary.md:111-153` — distinguish Phase 0 drift
  enforcement from Phase 1 type-level enforcement.
- `scripts/conformance/closure-scope.json` — freeze the exact Phase 0 source,
  binary, manifest, and image identities.
- `scripts/conformance/oracle-cache.jsonl` — commit the legitimate canonical
  refresh produced by the exhaustive Phase 0 run.
- `docs/superpowers/plans/2026-08-19-authority-enforced-kernel-closure-roadmap.md`
  — record Phase 0 completion and the measured next-plan input.

---

### Task 1: Make the typed-domain gate deterministic and offline

**Files:**
- Create: `scripts/lint-domains.sh`
- Create: `scripts/tests/test_lint_domains.py`
- Modify: `justfile:89-110`

**Interfaces:**
- Consumes: local `semgrep`, `.semgrep/`, `crates/`, caller-provided
  `SSL_CERT_FILE`, `SEMGREP_BIN`, and `SEMGREP_LOG_FILE` overrides.
- Produces: `scripts/lint-domains.sh`, exiting exactly with Semgrep's status;
  `just lint-domains` invokes it from the repository root.

- [ ] **Step 1: Write the failing launcher tests**

Create `scripts/tests/test_lint_domains.py` with these contracts:

```python
#!/usr/bin/env python3

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "lint-domains.sh"


class LintDomainsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.capture = self.root / "capture.json"
        self.cert = self.root / "cert.pem"
        self.cert.write_text("fixture certificate bundle\n", encoding="utf-8")
        self.fake = self.root / "semgrep"
        self.fake.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['CAPTURE']).write_text(json.dumps({\n"
            "  'argv': sys.argv[1:],\n"
            "  'ssl': os.environ.get('SSL_CERT_FILE'),\n"
            "  'log': os.environ.get('SEMGREP_LOG_FILE'),\n"
            "  'metrics': os.environ.get('SEMGREP_SEND_METRICS'),\n"
            "  'version_check': os.environ.get('SEMGREP_ENABLE_VERSION_CHECK'),\n"
            "  'otel': os.environ.get('OTEL_SDK_DISABLED'),\n"
            "}))\n"
            "raise SystemExit(int(os.environ.get('FAKE_STATUS', '0')))\n",
            encoding="utf-8",
        )
        self.fake.chmod(0o755)

    def tearDown(self):
        self.temp.cleanup()

    def run_launcher(self, status="0"):
        env = os.environ.copy()
        env.update(
            {
                "SEMGREP_BIN": str(self.fake),
                "SSL_CERT_FILE": str(self.cert),
                "SEMGREP_LOG_FILE": str(self.root / "semgrep.log"),
                "CAPTURE": str(self.capture),
                "FAKE_STATUS": status,
            }
        )
        return subprocess.run([str(SCRIPT)], cwd=ROOT, env=env, text=True)

    def test_launcher_is_offline_and_uses_explicit_writable_paths(self):
        result = self.run_launcher()
        self.assertEqual(result.returncode, 0)
        capture = json.loads(self.capture.read_text(encoding="utf-8"))
        self.assertEqual(capture["ssl"], str(self.cert))
        self.assertEqual(capture["log"], str(self.root / "semgrep.log"))
        self.assertEqual(capture["metrics"], "off")
        self.assertEqual(capture["version_check"], "0")
        self.assertEqual(capture["otel"], "true")
        self.assertEqual(
            capture["argv"],
            ["--config", ".semgrep/", "crates/", "--severity", "ERROR", "--error", "--quiet"],
        )

    def test_launcher_preserves_semgrep_failure(self):
        self.assertEqual(self.run_launcher("7").returncode, 7)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the tests and verify the launcher is absent**

Run:

```bash
python3 scripts/tests/test_lint_domains.py
```

Expected: ERROR/FAIL because `scripts/lint-domains.sh` does not exist.

- [ ] **Step 3: Implement the deterministic launcher**

Create `scripts/lint-domains.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

semgrep_bin="${SEMGREP_BIN:-semgrep}"
if ! command -v "$semgrep_bin" >/dev/null 2>&1; then
    echo "error: semgrep is not installed, so the typed-domain gate cannot run." >&2
    exit 1
fi

if [[ -z "${SSL_CERT_FILE:-}" || ! -r "${SSL_CERT_FILE}" ]]; then
    for candidate in \
        /etc/ssl/cert.pem \
        /etc/ssl/certs/ca-certificates.crt \
        /opt/homebrew/etc/ca-certificates/cert.pem
    do
        if [[ -r "$candidate" ]]; then
            export SSL_CERT_FILE="$candidate"
            break
        fi
    done
fi
if [[ -z "${SSL_CERT_FILE:-}" || ! -r "${SSL_CERT_FILE}" ]]; then
    echo "error: no readable CA bundle for semgrep; set SSL_CERT_FILE." >&2
    exit 1
fi

lint_tmp="$(mktemp -d "${TMPDIR:-/tmp}/carrick-semgrep.XXXXXX")"
trap 'rm -rf "$lint_tmp"' EXIT
export SEMGREP_LOG_FILE="${SEMGREP_LOG_FILE:-$lint_tmp/semgrep.log}"
export SEMGREP_SEND_METRICS=off
export SEMGREP_ENABLE_VERSION_CHECK=0
export OTEL_SDK_DISABLED=true

"$semgrep_bin" --config .semgrep/ crates/ --severity ERROR --error --quiet
```

Make it executable. Replace the inline Semgrep invocation in `justfile` with:

```just
lint-domains:
    ./scripts/lint-domains.sh
```

- [ ] **Step 4: Run the focused and real gates**

Run:

```bash
python3 scripts/tests/test_lint_domains.py
just lint-domains
```

Expected: both exit 0. The real scan must produce no CA-store or unwritable-log
error. Do not accept a skip or missing-tool warning.

- [ ] **Step 5: Commit the deterministic launcher**

```bash
git add scripts/lint-domains.sh scripts/tests/test_lint_domains.py justfile
git commit -m "build: make typed-domain lint deterministic offline"
```

---

### Task 2: Freeze and classify guest-facing host transitions — superseded

The lexical Rust parser originally specified here was rejected at breaker. Do
not recreate or execute it. The authoritative replacement is:

- design:
  `docs/superpowers/specs/2026-08-20-compiler-resolved-host-authority-census-design.md`;
- implementation plan:
  `docs/superpowers/plans/2026-08-20-compiler-resolved-host-authority-census.md`.

Commits `31fb071f6` through `d13bb4cc3` remain rejected evidence: their
failures demonstrated that a lexical scanner could miss valid cfg siblings,
aliases, function values, standalone-target reachability, and omitted watched
operations. They are not Phase 0 closure.

The replacement boundary keeps these facts separate:

1. Pinned Clippy diagnostics establish the resolved callsite census only for
   product profiles actually executed. The local macOS gate executes the CLI,
   runtime, and HVF profiles.
2. An independent checked compiler-capture receipt binds the catalog,
   diagnostics, and exact profile memberships. Structured review validation
   detects drift and malformed evidence; human review supplies semantic truth.
3. The current local inventory contains 682 rows, including 173
   `forbidden_semantic` rows. Those rows are known debt, not accepted authority
   or completed fixes.
4. Linux, FreeBSD, and NetBSD CLI/runtime profiles remain pending. A passing
   three-profile local check is explicitly partial, not cross-platform
   completeness.
5. Narrow Semgrep rules deny unmistakable catalog escape hatches outside exact
   reviewed boundary modules. Phase 1 must still introduce the typed
   host-capability facade and deny raw host APIs outside it.

The normal gate is read-only:

```bash
./scripts/lint-domains.sh
python3 scripts/migrate/check-host-authority-transitions.py --check
```

A compiler census, independent receipt, and reviewed classification are all
required. None alone proves semantic containment.

---

### Task 3: Make every syscall authority declaration explicit

**Files:**
- Modify: `crates/carrick-abi/src/syscall.rs:47-168,268-654`
- Modify: `crates/carrick-runtime/tests/integration/syscall_table.rs:260-320`

**Interfaces:**
- Consumes: existing `Authority::{Guest,Host,Hybrid}` behavior.
- Produces:
  `const fn syscall(number, name, group, support, authority) -> Syscall`; every
  one of the 338 table rows supplies the fifth argument; no
  `authority_for_aarch64` symbol or catch-all remains.

- [ ] **Step 1: Add the red explicitness contract**

Add this test beside `authority_partition_matches_host_boundary_rules`:

```rust
#[test]
fn every_aarch64_syscall_spells_its_authority_at_the_table_row() {
    let source = include_str!("../../../carrick-abi/src/syscall.rs");
    assert!(
        !source.contains("authority_for_aarch64"),
        "authority must not come from a range/default classifier",
    );
    let table = source
        .split_once("const AARCH64_SYSCALLS: &[Syscall] = &[")
        .expect("AARCH64 table marker")
        .1
        .split_once("];\n\n// Compile-time guard")
        .expect("AARCH64 table terminator")
        .0;
    assert_eq!(
        table.matches("Authority::").count(),
        aarch64_table().len(),
        "each syscall row must contain exactly one explicit authority",
    );
}
```

- [ ] **Step 2: Run the contract and verify it fails**

```bash
cargo test -p carrick-runtime --test integration \
  every_aarch64_syscall_spells_its_authority_at_the_table_row -- --exact
```

Expected: FAIL because `authority_for_aarch64` exists and table rows do not
contain `Authority::...`.

- [ ] **Step 3: Change the constructor and remove the classifier**

Change the constructor to:

```rust
const fn syscall(
    number: u64,
    name: &'static str,
    group: &'static str,
    support: SupportLevel,
    authority: Authority,
) -> Syscall {
    Syscall {
        number,
        name,
        group,
        subsystem: group,
        support,
        handler: handler_for_aarch64(number),
        authority,
        compat_note: compat_note_for_aarch64(number),
    }
}
```

Delete `authority_for_aarch64`. Add exactly one fifth argument to every table
row, preserving its current classification with this exhaustive rule:

- `Authority::Host`: syscall 124; 101, 115, 407; 198-212, 242, 243, 269, 417,
  441; 0-18, 23-29, 32-57, 59-73, 75-84, 88, 213, 262-265, 267, 276, 279,
  285-287, 291, 292, 412-414, 416, 428-433, 436, 437, 439, 442, 443, 451,
  452, 457, 458; and 278.
- `Authority::Hybrid`: 186-189, 194-197; 113, 114, 169, 171, 266, 403, 405,
  406; 214-216, 222-239, 282, 284, 288-290, 425-427, 440, 447, 450, 453,
  462.
- `Authority::Guest`: every other declared row.

Use `apply_patch` for the source edit and `cargo fmt --all` for mechanical
formatting. Do not change any classification in this task; incorrect
classifications move only with Docker evidence and a separate red-first change.

- [ ] **Step 4: Verify explicitness and preserved representatives**

```bash
cargo test -p carrick-runtime --test integration \
  every_aarch64_syscall_spells_its_authority_at_the_table_row -- --exact
cargo test -p carrick-runtime --test integration \
  authority_partition_matches_host_boundary_rules -- --exact
cargo test -p carrick-runtime --test integration \
  aarch64_syscall_table_is_sorted_for_binary_search -- --exact
```

Expected: all PASS.

- [ ] **Step 5: Commit explicit authority**

```bash
git add crates/carrick-abi/src/syscall.rs \
  crates/carrick-runtime/tests/integration/syscall_table.rs
git commit -m "refactor(abi): make syscall authority explicit"
```

---

### Task 4: Make the documented enforcement boundary honest

**Files:**
- Modify: `docs/host-facility-boundary.md:111-153`
- Modify:
  `docs/superpowers/plans/2026-08-19-authority-enforced-kernel-closure-roadmap.md`

**Interfaces:**
- Consumes: deterministic Semgrep launcher, checked transition inventory, and
  explicit syscall rows from Tasks 1-3.
- Produces: documentation that distinguishes current Phase 0 drift prevention
  from future Phase 1 type-level capability enforcement.

- [ ] **Step 1: Replace the false Semgrep-only claim**

Rewrite “Make it mechanical, not aspirational” to state all four facts:

```markdown
1. Every syscall row spells `Authority::{Guest,Host,Hybrid}` explicitly; there
   is no catch-all classifier.
2. `just lint-domains` runs Semgrep offline and validates the reviewed
   `host-authority-transition-inventory.json`; either tool missing or any drift
   fails the gate.
3. The Phase 0 inventory prevents new ambient host calls and makes legacy and
   backing/substrate uses reviewable. It does not prove dynamic reachability.
4. Type-level handler contexts and named capabilities are Phase 1. Until they
   land, this is a drift boundary, not structural proof that every Guest path
   is unable to call host authority.
```

Do not mark any inventory row fixed merely because it is classified.

- [ ] **Step 2: Run documentation-adjacent gates**

```bash
just lint-domains
just fmt-check
```

Expected: PASS.

- [ ] **Step 3: Commit the honest boundary**

```bash
git add docs/host-facility-boundary.md \
  docs/superpowers/plans/2026-08-19-authority-enforced-kernel-closure-roadmap.md
git commit -m "docs: distinguish authority drift and structural enforcement"
```

---

### Task 5: Pass the complete local gate before measuring guests

**Files:**
- Modify only if a gate exposes a real Task 1-4 defect. Keep each fix in a
  separate commit naming the task that introduced it.

**Interfaces:**
- Consumes: Tasks 1-4.
- Produces: a clean source revision whose complete non-guest local gate passes.

- [ ] **Step 1: Re-run every new focused contract**

```bash
python3 scripts/tests/test_lint_domains.py
python3 scripts/tests/test_host_authority_transitions.py
cargo test -p carrick-runtime --test integration \
  every_aarch64_syscall_spells_its_authority_at_the_table_row -- --exact
cargo test -p carrick-runtime --test integration \
  authority_partition_matches_host_boundary_rules -- --exact
just lint-domains
```

Expected: all PASS.

- [ ] **Step 2: Run the repository gate serially**

```bash
RUST_TEST_THREADS=1 just ci
```

Expected: exit 0 through frame-pointer, formatting, clippy, authority lint,
deny, matrix drift, compile, docs, host tests, and integration tests. Record
wall time and the final successful recipe in the Phase 0 report notes.

- [ ] **Step 3: Confirm the source tree is clean**

```bash
git status --short
git rev-parse HEAD
```

Expected: no status rows and one commit hash. If a gate required a fix, add a
narrow fix commit before proceeding; do not hide it in the measurement receipt.

---

### Task 6: Build once, record identity, and freeze the exact closure scope

**Files:**
- Modify: `scripts/conformance/closure-scope.json`
- Create: `docs/perf-results/2026-08-19-authority-phase0/README.md`

**Interfaces:**
- Consumes: the clean Task 5 HEAD, Docker registries/images, signed Carrick
  build, and `closure-scope.py`.
- Produces: one immutable signed Carrick binary and a committed scope record
  binding its source, bytes, manifest, and four live image identities.

- [ ] **Step 1: Bootstrap registries and build the signed artifact once**

Run the durable driver in dry-run mode so it prepares registries/images and
builds/signs without executing suites:

```bash
scripts/conformance/run-full.sh --dry-run
docker pull localhost:5050/ltp:arm64
docker pull localhost:5050/cpython-test:3.12.13
docker pull localhost:5005/carrick-go-conformance:1.24
docker pull localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0
```

Expected: registry setup completes, `scripts/build-signed.sh` succeeds, and the
harness prints a 2,127-suite plan. All four local image inspections must now
succeed; `closure-scope.py` reads the local Docker store even when the registry
already serves the tag. From this point until Task 7 completes, do not run
`just build`, `just conformance*`, or `run-full.sh` again; each can relink and
change the claimed artifact.

- [ ] **Step 2: Capture the artifact identity**

Run and save the complete outputs for the report:

```bash
git rev-parse HEAD
shasum -a 256 target/release/carrick
codesign --verify --strict target/release/carrick
codesign -dvvv target/release/carrick
codesign -d --entitlements :- target/release/carrick
/usr/bin/dwarfdump --uuid target/release/carrick
otool -l target/release/carrick | rg '__dof_carrick'
```

Expected: signature verification succeeds; entitlements contain
`com.apple.security.hypervisor`; one LC_UUID is present; `__dof_carrick` is
present.

- [ ] **Step 3: Freeze and check the scope**

```bash
python3 scripts/conformance/closure-scope.py freeze \
  scripts/conformance/closure-scope.json
python3 scripts/conformance/closure-scope.py check \
  scripts/conformance/closure-scope.json
```

Expected: both commands report exactly 2,127 suites and resolve all four image
identities. The source tree now differs only by the scope JSON and report.

- [ ] **Step 4: Create the Phase 0 report skeleton**

Create `docs/perf-results/2026-08-19-authority-phase0/README.md` with:

```markdown
# Authority Phase 0 — trustworthy baseline

## Authority

- design spec: `docs/superpowers/specs/2026-08-19-authority-enforced-kernel-closure-design.md`
- binary source HEAD: exact value printed by `git rev-parse HEAD`
- binary SHA-256: exact value printed by `shasum -a 256`
- CDHash: exact value printed by `codesign -dvvv`
- LC_UUID: exact value printed by `dwarfdump --uuid`
- hypervisor entitlement: present
- `__dof_carrick`: present
- closure scope: 2,127 suites, four resolved image identities

## Local gates

- focused authority contracts: PASS
- `just lint-domains`: PASS
- `RUST_TEST_THREADS=1 just ci`: PASS, followed by its exact measured wall time

## Phase 0 claim boundary

This checkpoint makes current syscall authority and source transitions explicit
and drift-gated. It does not prove type-level containment, exact conformance, or
lifecycle performance closure.
```

Replace every descriptive value source with the captured literal before
committing; the evidence-field scan in Task 7 rejects any survivor.

- [ ] **Step 5: Commit the scope without rebuilding**

```bash
git add scripts/conformance/closure-scope.json \
  docs/perf-results/2026-08-19-authority-phase0/README.md
git commit -m "test(conformance): freeze authority phase zero artifact"
```

The binary source HEAD recorded in the scope is now the parent/ancestor of this
tooling/report commit. Do not rebuild.

---

### Task 7: Run exhaustive Phase 0 closure and publish the measured ledger

**Files:**
- Modify: `scripts/conformance/oracle-cache.jsonl`
- Modify: `docs/perf-results/2026-08-19-authority-phase0/README.md`
- Modify:
  `docs/superpowers/plans/2026-08-19-authority-enforced-kernel-closure-roadmap.md`
- Create under ignored `target/conformance/authority-phase0/`: suite results,
  suite log, probe log, and raw outputs.

**Interfaces:**
- Consumes: the unchanged signed binary and frozen scope from Task 6.
- Produces: exactly 2,127 suite reports, the complete closure-mode arm64
  musl/GNU probe inventory, refreshed canonical oracle cache, rendered backlog,
  and a durable Phase 0 receipt.

- [ ] **Step 1: Prove the scope still matches before execution**

```bash
python3 scripts/conformance/closure-scope.py check \
  scripts/conformance/closure-scope.json
mkdir -p target/conformance/authority-phase0
```

Expected: scope check passes. If it fails, stop; do not repair by rebuilding or
re-freezing without explaining the drift in a new commit.

- [ ] **Step 2: Run all Carrick suites, then all Docker oracles**

Run the harness directly so the binary is not relinked:

```bash
suite_status=0
target/release/carrick-conformance \
  --tier full \
  --lane hvf \
  --closure \
  --force \
  --refresh-oracle \
  --workers 8 \
  --cpython-workers 4 \
  --carrick-bin target/release/carrick \
  --jsonl target/conformance/authority-phase0/results.jsonl \
  >target/conformance/authority-phase0/suites.log 2>&1 \
  || suite_status=$?
printf 'suite closure status=%d\n' "$suite_status"
```

Expected: nonzero is likely because Phase 0 measures open gaps, but the log must
show all 2,127 Carrick runs followed by the Docker phase. It must not show an
early abort, overlap, retry, allow-hang, bless, or missing oracle. Preserve the
exit status in the report.

- [ ] **Step 3: Run strict probe phases without rebuilding Carrick**

```bash
./scripts/build-probes.sh --closure-arm64 \
  >target/conformance/authority-phase0/probes-build.log 2>&1
: >target/conformance/authority-phase0/probes.log
generic_status=0
CARRICK_PROBE_MODE=closure \
CARRICK_PROBE_LANE=arm64 \
CARRICK_EXEC_BACKEND=hvpatch \
  cargo test -p carrick-cli --test conformance conformance_probes \
    -- --exact --nocapture \
    >>target/conformance/authority-phase0/probes.log 2>&1 \
    || generic_status=$?
dedicated_status=0
python3 scripts/conformance/closure-probe-scenarios.py \
  >>target/conformance/authority-phase0/probes.log 2>&1 \
  || dedicated_status=$?
printf 'probe closure statuses: generic=%d dedicated=%d\n' \
  "$generic_status" "$dedicated_status"
```

Run both probe commands even when the generic phase is red; capture their
individual exit statuses in the report. Do not invoke the `just` recipe because
its `build` prerequisite would relink the signed Carrick binary.

- [ ] **Step 4: Render and validate the complete backlog**

```bash
python3 scripts/conformance/closure-report.py \
  --scope scripts/conformance/closure-scope.json \
  --results target/conformance/authority-phase0/results.jsonl \
  --probe-log target/conformance/authority-phase0/probes.log \
  --output target/conformance/authority-phase0/closure-ledger.md
```

Expected: the reporter accepts exactly 2,127 suite rows and the complete probe
inventory. Copy its machine-derived totals and ranked categories into the Phase
0 README; do not hand-count logs.

- [ ] **Step 5: Verify artifact identity and scoped cleanup**

Repeat the Task 6 identity commands and compare them byte-for-byte with the
report. Then use the run IDs from `results.jsonl` with
`scripts/sudo/kill.sh <run-id>` and verify no matching Carrick or Docker
containers remain. Record cleanup commands and zero-leftover results.

- [ ] **Step 6: Finish the durable Phase 0 report**

Append these sections with exact machine-derived values and paths:

```markdown
## Source-transition inventory

- total rows and counts by kind/classification
- every `forbidden_semantic` row, grouped by mechanism
- every `legacy_unreachable` row, including its discriminator
- statement that classification prevents drift but does not prove reachability

## Closure result

- suite MATCH/non-match counts
- semantic, infrastructure, unexercised, and pathological counts
- complete probe PASS/FAIL/infrastructure counts
- top mechanism clusters from `closure-ledger.md`
- exact suite/probe exit statuses

## Cleanup and provenance

- unchanged post-run binary identity
- scoped Carrick and Docker cleanup receipts
- SHA-256 for results, suite log, probe log, scope, inventory, and oracle cache

## Phase 0 verdict

- proved: deterministic gates, explicit authority rows, reviewed drift inventory,
  exact current signed baseline
- not proved: type-level host containment, zero semantic host transitions,
  exact conformance, lifecycle <=1.0x, ecosystem <=2.0x
- next plan input: ranked forbidden-semantic mechanisms and fresh closure clusters
```

Do not use “green” for a red closure run. Do not convert current failures into a
baseline or `known_gaps`.

- [ ] **Step 7: Update the campaign roadmap**

Change the roadmap Current State section to record:

- Phase 0 source, scope, and report commits;
- exact measured closure/probe totals;
- authority inventory totals; and
- the evidence-selected first Phase 1 capability boundary.

Keep Phases 1-7 pending and the thread goal active.

- [ ] **Step 8: Run final Phase 0 verification and commit receipts**

```bash
python3 scripts/migrate/check-host-authority-transitions.py
just lint-domains
python3 scripts/conformance/closure-scope.py check \
  scripts/conformance/closure-scope.json
rg -n 'exact value printed|exact measured wall time' \
  docs/perf-results/2026-08-19-authority-phase0/README.md
git diff --check
```

Expected: the first three commands pass; placeholder search prints nothing;
`git diff --check` prints nothing.

Commit the legitimate canonical cache refresh and durable receipts:

```bash
git add scripts/conformance/oracle-cache.jsonl \
  docs/perf-results/2026-08-19-authority-phase0/README.md \
  docs/superpowers/plans/2026-08-19-authority-enforced-kernel-closure-roadmap.md
git commit -m "docs(conformance): record authority phase zero baseline"
```

Do not bless `baseline.jsonl`, change `docs/support-matrix.md`, or mark the
thread goal complete.
