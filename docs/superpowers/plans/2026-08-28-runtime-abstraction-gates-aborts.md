# Runtime Abstraction Gates and Abort Ledger Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record the two controller decisions, make process-global scope and host-PID crossings fail closed, and classify every raw carrier abort into a monotone reviewed ledger.

**Architecture:** Reuse Carrick's compiler-resolved host-authority census for host PID APIs rather than adding a competing source scanner. Add one stable, source-fingerprinted global-state ledger and one sharded raw-abort ledger; both reject additions, stale entries, duplicate identities, and silent source changes. The abort shards are file-disjoint so large classifications can be delegated safely and reviewed independently.

**Tech Stack:** Python 3 standard library, Cargo/Clippy JSON diagnostics, checked JSON ledgers, Rust 2024, `just lint-domains`.

**Spec:** [`docs/runtime-abstraction-audit-2026-08-27.md`](../runtime-abstraction-audit-2026-08-27.md), extending [`docs/identity-and-scope-domains.md`](../identity-and-scope-domains.md).

## Global Constraints

- Current source, not the audit's `28a8678c4` line numbers or counts, is authoritative.
- The `carrick-embed` census supersedes the proposed `CarrierGlobal<T>` wrapper. Do not build both.
- FileAuthority is one canonical in-carrier direct core. The retired host-helper/IPC route is not a second required production transport.
- Existing `scripts/migrate/check-host-authority-transitions.py` remains the sole compiler-resolved host-operation census.
- A new ledger entry is a gate failure, not an automatic refresh. Existing ledgers can only shrink.
- A moved or changed source site must be reviewed: stable keys exclude line numbers but include a normalized declaration/call fingerprint.
- Never refresh unrelated host-authority inventory to hide positional drift. `changed=[]` remains baseline-red evidence, not authority to re-bless it.
- Every delegated write worker gets its own manually based worktree and an exact verification command.
- Every code change is red-first and ends with `git diff --check`, focused tests, `just fmt-check`, `just clippy`, `just lint-domains`, and `just test` before integration.

## File Structure

| Path | Responsibility |
|---|---|
| `docs/identity-and-scope-domains.md` | Accepted scope-gate decision and link to the executable ledger. |
| `docs/superpowers/plans/2026-08-12-per-run-file-authority-atomic-migration.md` | Direct-core amendment removing retired helper/IPC production requirements. |
| `docs/runtime-abstraction-audit-2026-08-27.md` | Accepted answers to its two person-decision questions. |
| `scripts/migrate/check-runtime-global-state.py` | Token-aware discovery and exact monotone comparison for process-global state/env sources. |
| `scripts/migrate/test-runtime-global-state.py` | Synthetic red/green tests for additions, removals, source drift, comments and strings. |
| `scripts/migrate/runtime-global-state.json` | Reviewed current global-state rows, classified by scope. |
| `scripts/migrate/check-runtime-aborts.py` | Raw `std::process::abort()` discovery and sharded exact-ledger gate. |
| `scripts/migrate/test-runtime-aborts.py` | Synthetic red/green tests for abort discovery and ledger monotonicity. |
| `scripts/migrate/runtime-aborts/vcpu-loop.json` | `carrick-runtime/src/vcpu_loop/**` classifications. |
| `scripts/migrate/runtime-aborts/runtime.json` | Remaining `carrick-runtime/src/**` classifications. |
| `scripts/migrate/runtime-aborts/hvf.json` | `carrick-vmm-hvf/src/**` classifications. |
| `clippy.toml` | Adds `libc::proc_listallpids` to the compiler-resolved host-operation catalog. |
| `scripts/migrate/host-authority-catalog.json` | Stable catalog id and semantic authority for `proc_listallpids`. |
| `scripts/migrate/check-host-authority-transitions.py` | Catalog completeness assertion only; do not add a second scanner. |
| `justfile` | Runs the two new gates from `lint-domains`. |

---

## Task 1: Record the two accepted architecture decisions

**Files:**
- Modify: `docs/identity-and-scope-domains.md`
- Modify: `docs/superpowers/plans/2026-08-12-per-run-file-authority-atomic-migration.md`
- Modify: `docs/runtime-abstraction-audit-2026-08-27.md`
- Test: `crates/carrick-runtime/src/file_authority/root.rs`

**Interfaces:**
- Consumes: current `Container`/`LaunchContext` scope model, `FileAuthorityRun::direct_root`.
- Produces: one written answer for each decision, with no second wrapper or retired production transport left scheduled.

- [ ] **Step 1: Add a source-shape test that is red before the document amendments**

In `crates/carrick-runtime/src/file_authority/root.rs` extend the existing
`file_authority_has_no_host_helper_process_path` test with a compile-time read
of the approved migration document and require these exact decision markers:

```rust
let plan = include_str!(
    "../../../../docs/superpowers/plans/2026-08-12-per-run-file-authority-atomic-migration.md"
);
assert!(plan.contains("Decision 2026-08-28: direct canonical core"));
assert!(plan.contains("host-helper and IPC production transports are retired"));
assert!(!plan.contains("direct and IPC model tests are identical;"));
```

- [ ] **Step 2: Run the focused test and prove RED**

Run:

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib \
  file_authority_has_no_host_helper_process_path -- --exact --test-threads=1
```

Expected: FAIL because the decision marker is absent and the old completion
requirement remains.

- [ ] **Step 3: Amend the documents, preserving their historical record**

Add a dated decision block to `identity-and-scope-domains.md`:

```markdown
### Accepted scope implementation — 2026-08-28

The reviewed `carrick-embed` census plus the monotone
`runtime-global-state.json` gate supersedes the proposed `CarrierGlobal<T>` /
`CarrierScope` wrapper. Container state is carried by `Container` and
`LaunchContext`; accepted carrier infrastructure remains explicit ledger debt.
Do not build both mechanisms.
```

In the FileAuthority migration plan preserve Waves 1–3 as history, but add:

```markdown
### Decision 2026-08-28: direct canonical core

The host-helper and IPC production transports are retired with the legacy
host-process execution backends. `FileAuthorityTransport` remains an internal
test/direct-call seam, with `DirectFileAuthority` its sole production
implementation. Completion requires one canonical in-carrier core and must not
require helper lifecycle, IPC equivalence, or helper-death behavior.
```

Strike or mark superseded every future-tense helper/IPC requirement in the
completion checklist. In the runtime audit's Sequencing section record both
accepted answers and link to the dated blocks.

- [ ] **Step 4: Run the focused test and document-link checks**

Run:

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime --lib \
  file_authority_has_no_host_helper_process_path -- --exact --test-threads=1
rg -n 'Accepted scope implementation|Decision 2026-08-28: direct canonical core' \
  docs/identity-and-scope-domains.md \
  docs/superpowers/plans/2026-08-12-per-run-file-authority-atomic-migration.md \
  docs/runtime-abstraction-audit-2026-08-27.md
```

Expected: PASS and one accepted answer for each decision.

- [ ] **Step 5: Commit**

```bash
git add docs/identity-and-scope-domains.md \
  docs/superpowers/plans/2026-08-12-per-run-file-authority-atomic-migration.md \
  docs/runtime-abstraction-audit-2026-08-27.md \
  crates/carrick-runtime/src/file_authority/root.rs
git commit -m "docs(runtime): resolve abstraction audit decisions"
```

---

## Task 2: Gate process-global state with a stable monotone ledger

**Files:**
- Create: `scripts/migrate/check-runtime-global-state.py`
- Create: `scripts/migrate/test-runtime-global-state.py`
- Create: `scripts/migrate/runtime-global-state.json`
- Modify: `justfile`
- Modify: `docs/identity-and-scope-domains-embed-census.md`

**Interfaces:**
- Consumes: the checked embed census classifications and source roots
  `crates/carrick-runtime/src`, `crates/carrick-kernel/src`,
  `crates/carrick-vmm-hvf/src`.
- Produces: `discover(root) -> tuple[Finding, ...]` and an exact checker whose
  checked inventory can only shrink.

- [ ] **Step 1: Write synthetic failing tests before the scanner exists**

The test module imports the checker with `importlib.util` and creates scratch
Rust trees. The checker exposes `scan_source(path, source)`,
`compare(actual, reviewed)`, and `LedgerError`; write these concrete tests:

```python
class RuntimeGlobalStateTests(unittest.TestCase):
    def test_discovers_multiline_static_and_env_sources(self):
        source = r'''static mut RAW: u64 = 0;
static CELL: OnceLock<u64> = OnceLock::new();
thread_local! { static TLS: Cell<u8> = const { Cell::new(0) }; }
fn config() { let _ = std::env::var("CARRICK_RUN_ID"); }
'''
        findings = scan_source(Path("crates/x/src/lib.rs"), source)
        self.assertEqual(
            [(row.kind, row.symbol) for row in findings],
            [("static", "RAW"), ("static", "CELL"),
             ("thread_local", "TLS"), ("env_var", "config::CARRICK_RUN_ID")],
        )

    def test_ignores_comments_strings_and_lifetimes(self):
        source = r'''// static FAKE: u8 = 0;
const TEXT: &str = "std::env::var(\\\"FAKE\\\")";
fn borrow(value: &'static str) -> &'static str { value }
'''
        self.assertEqual(scan_source(Path("crates/x/src/lib.rs"), source), ())

    def test_cfg_test_policy_is_deterministic(self):
        source = "#[cfg(test)] static TEST_CELL: AtomicU64 = AtomicU64::new(0);"
        rows = scan_source(Path("crates/x/src/lib.rs"), source)
        self.assertEqual([(row.kind, row.symbol) for row in rows],
                         [("static", "TEST_CELL")])

    def test_exact_ledger_rejects_add_remove_drift_and_bad_rows(self):
        finding = Finding("static", "crates/x/src/lib.rs", "CELL", "a" * 64)
        reviewed = reviewed_row(finding, classification="carrier_infra")
        compare((finding,), (reviewed,))
        for actual, rows in [((finding,), ()), ((), (reviewed,))]:
            with self.assertRaises(LedgerError):
                compare(actual, rows)
        with self.assertRaises(LedgerError):
            compare((dataclasses.replace(finding, fingerprint="b" * 64),),
                    (reviewed,))
        with self.assertRaises(LedgerError):
            compare((finding,), (reviewed, reviewed))
        with self.assertRaises(LedgerError):
            compare((finding,),
                    (reviewed_row(finding, classification="unknown"),))

    def test_line_only_move_keeps_identity(self):
        one = scan_source(Path("crates/x/src/lib.rs"),
                          "static CELL: AtomicU64 = AtomicU64::new(0);")
        two = scan_source(Path("crates/x/src/lib.rs"),
                          "\n\nstatic CELL: AtomicU64 = AtomicU64::new(0);")
        self.assertEqual(one, two)
```

Fixtures must include `static mut`, `static NAME: OnceLock<T>`, a multiline
initializer, function-local `static`, `thread_local!`, `std::env::var`,
`std::env::var_os`, comments containing `static`, string literals containing
`std::env::var`, and a Rust lifetime such as `&'static str`.

- [ ] **Step 2: Prove the tests RED**

Run:

```bash
python3 scripts/migrate/test-runtime-global-state.py
```

Expected: FAIL because the checker module does not exist.

- [ ] **Step 3: Implement token-aware discovery**

Use a small lexer, not a line regex. It must skip nested block comments, line
comments, normal/raw/byte strings and char literals, retain token byte spans,
and balance delimiters through the terminating semicolon. Define:

```python
@dataclass(frozen=True, order=True)
class Finding:
    kind: str                 # static | thread_local | env_var | env_var_os
    file: str
    symbol: str
    fingerprint: str          # sha256(normalized tokens), never a line number

ALLOWED_CLASSIFICATIONS = {
    "container_debt",
    "carrier_infra",
    "host_kernel_object",
    "monotonic_allocator",
    "config_debug",
    "test_only",
}
```

`normalize_tokens` joins lexical tokens with one ASCII space. The stable row
identity is `(kind, file, symbol)`; a fingerprint mismatch is source drift and
must fail. No `--refresh` mode is shipped. A `--bootstrap` mode may print rows
to stdout only and must refuse to overwrite the checked ledger.

The ledger schema is:

```json
{
  "schema": 1,
  "rows": [
    {
      "kind": "static",
      "file": "crates/carrick-runtime/src/kernel/netns.rs",
      "symbol": "root_net_ns::ROOT",
      "fingerprint": "0000000000000000000000000000000000000000000000000000000000000000",
      "classification": "container_debt",
      "destination": "Container.net_ns",
      "rationale": "Initial network namespace is per Linux container."
    }
  ]
}
```

Require nonempty `destination` for `container_debt` and nonempty `rationale`
for every row.

- [ ] **Step 4: Make the synthetic suite GREEN**

Run:

```bash
python3 scripts/migrate/test-runtime-global-state.py
```

Expected: PASS with every red-shape exercised.

- [ ] **Step 5: Seed the checked ledger from the reviewed census**

Run the print-only bootstrap, classify every current finding at the individual
site (not by file), and reconcile each row with
`identity-and-scope-domains-embed-census.md`. Preserve the two current
`kernel/netns.rs` root namespace cells as `container_debt`; do not relabel them
carrier infrastructure merely to make the gate green. Add the checked ledger
path and exact current counts per classification to the census document.

- [ ] **Step 6: Wire the gate and prove addition/removal failures against a copy**

Add to `lint-domains` before the expensive compiler census:

```just
python3 scripts/migrate/check-runtime-global-state.py --check
```

Run:

```bash
python3 scripts/migrate/check-runtime-global-state.py --check
python3 scripts/migrate/test-runtime-global-state.py
just lint-domains
```

Expected: the new gate passes. The pre-existing host-authority positional stop
may still report `changed=[]`; do not refresh it in this task.

- [ ] **Step 7: Commit**

```bash
git add scripts/migrate/check-runtime-global-state.py \
  scripts/migrate/test-runtime-global-state.py \
  scripts/migrate/runtime-global-state.json \
  docs/identity-and-scope-domains-embed-census.md justfile
git commit -m "chore(runtime): gate process-global scope"
```

---

## Task 3: Complete the compiler-resolved host-PID gate

**Files:**
- Modify: `clippy.toml`
- Modify: `scripts/migrate/host-authority-catalog.json`
- Modify: `scripts/migrate/check-host-authority-transitions.py`
- Test: `scripts/tests/test_host_authority_transitions.py`

**Interfaces:**
- Consumes: existing `clippy::disallowed_methods` Cargo JSON census.
- Produces: catalog completeness for `libc::getpid`, `std::process::id`, and
  `libc::proc_listallpids`, with no parallel PID scanner.

- [ ] **Step 1: Add a failing catalog-completeness test**

```python
def test_linux_semantics_host_pid_operations_are_all_cataloged(self):
    operations = {entry["operation"] for entry in load_catalog()["entries"]}
    self.assertTrue({
        "libc::getpid",
        "std::process::id",
        "libc::proc_listallpids",
    } <= operations)
```

Also assert the same three paths occur exactly once in `clippy.toml`.

- [ ] **Step 2: Prove RED**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  scripts.tests.test_host_authority_transitions
```

Expected: FAIL because `proc_listallpids` is not cataloged.

- [ ] **Step 3: Add the missing compiler-resolved operation**

Add one disallowed method:

```toml
{ path = "libc::proc_listallpids", reason = "HA-CATALOG-PROCESS-LIST-ALL-PIDS: host process enumeration requires reviewed authority" },
```

Add the matching catalog row with semantic authority `authenticated_carrier`.
Raise `CATALOG_ENTRY_COUNT` by exactly one and make the required-PID set a
named constant asserted during catalog validation:

```python
REQUIRED_HOST_PID_OPERATIONS = {
    "libc::getpid",
    "std::process::id",
    "libc::proc_listallpids",
}
```

First repair the already-red test contract: the checked artifacts contain 640
rows while stale tests still assert 646. Reconcile those assertions from the
reviewed receipt, not by deleting tests. Then run the live macOS runtime/HVF
profiles. Current HEAD is expected to expose one new `std::process::id` site in
`dispatch/net.rs` plus the two production `proc_listallpids` calls in
`vfs/proc.rs`; classify those exact rows at the leaf. Both `proc_listallpids`
rows are Linux-semantics debt because their surrounding source already states
that host enumeration cannot see HVPatch tasks. Do not bulk-refresh unrelated
positional rows.

- [ ] **Step 4: Make tests and checker GREEN**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  scripts.tests.test_host_authority_transitions
python3 scripts/migrate/check-host-authority-transitions.py --static
python3 scripts/migrate/check-host-authority-transitions.py --check \
  --profiles macos-runtime-default,macos-hvf-default
```

Expected: unit suite and static checker PASS. The live subset must pass after
the exact new semantic rows are reviewed; positional-only changes elsewhere
must not be silently re-blessed. Before matrix-complete closure, execute the
full nine-profile receipt process required by the existing checker.

- [ ] **Step 5: Commit**

```bash
git add clippy.toml scripts/migrate/host-authority-catalog.json \
  scripts/migrate/check-host-authority-transitions.py \
  scripts/tests/test_host_authority_transitions.py \
  scripts/migrate/host-authority-transition-inventory.json \
  scripts/migrate/host-authority-macos-capture.json
git commit -m "chore(runtime): complete host pid authority catalog"
```

---

## Task 4: Build the sharded raw-abort gate

**Files:**
- Create: `scripts/migrate/check-runtime-aborts.py`
- Create: `scripts/migrate/test-runtime-aborts.py`
- Create: `scripts/migrate/runtime-aborts/vcpu-loop.json`
- Modify: `justfile`

**Interfaces:**
- Consumes: raw `std::process::abort()` calls under the configured Rust roots.
- Produces: stable per-call identities and exact sharded ledgers with
  `carrier_fault` versus `typed_error_debt` verdicts.

- [ ] **Step 1: Write the synthetic red suite**

The checker exposes `scan_abort_source(path, source)`,
`validate_shards(findings, ledgers)`, and `LedgerError`. Write:

```python
class RuntimeAbortLedgerTests(unittest.TestCase):
    def test_discovers_multiline_calls_and_distinguishes_ordinals(self):
        source = r'''fn publish() {
    if first_failed() { std::process::abort(); }
    if second_failed() { std::process::
        abort(); }
}'''
        rows = scan_abort_source(Path("crates/carrick-runtime/src/vcpu_loop/mod.rs"), source)
        self.assertEqual([(row.function, row.ordinal_in_function) for row in rows],
                         [("publish", 1), ("publish", 2)])
        self.assertNotEqual(rows[0].fingerprint, rows[1].fingerprint)

    def test_ignores_comments_strings_and_cfg_test_items(self):
        source = r'''// std::process::abort();
const TEXT: &str = "std::process::abort()";
#[cfg(test)] fn test_only() { std::process::abort(); }
'''
        self.assertEqual(
            scan_abort_source(Path("crates/carrick-runtime/src/lib.rs"), source), ())

    def test_exact_shards_reject_add_remove_drift_and_bad_metadata(self):
        finding = AbortFinding("crates/carrick-runtime/src/vcpu_loop/mod.rs",
                               "publish", 1, "a" * 64)
        good = abort_row(finding, verdict="typed_error_debt",
                         typed_error="PublishError")
        validate_shards((finding,), ledger_set([good], debt_ceiling=1))
        bad_cases = [
            ledger_set([], debt_ceiling=0),
            ledger_set([good, good], debt_ceiling=2),
            ledger_set([dict(good, verdict="unknown")], debt_ceiling=0),
            ledger_set([good], debt_ceiling=2),
            ledger_set([dict(good, fingerprint="b" * 64)], debt_ceiling=1),
        ]
        for ledgers in bad_cases:
            with self.subTest(ledgers=ledgers), self.assertRaises(LedgerError):
                validate_shards((finding,), ledgers)

    def test_wrong_shard_is_rejected(self):
        finding = AbortFinding("crates/carrick-vmm-hvf/src/trap.rs",
                               "run", 1, "c" * 64)
        row = abort_row(finding, verdict="carrier_fault", typed_error=None)
        with self.assertRaises(LedgerError):
            validate_shards((finding,), ledger_set([row], shard="runtime.json",
                                                   debt_ceiling=0))
```

- [ ] **Step 2: Prove RED**

Run:

```bash
python3 scripts/migrate/test-runtime-aborts.py
```

Expected: FAIL because the checker does not exist.

- [ ] **Step 3: Implement discovery and exact comparison**

Reuse the lexer module from Task 2 rather than maintaining a second comment /
string parser. Define:

```python
@dataclass(frozen=True, order=True)
class AbortFinding:
    file: str
    function: str
    ordinal_in_function: int
    fingerprint: str  # normalized enclosing statement + preceding message

ALLOWED_VERDICTS = {"carrier_fault", "typed_error_debt"}
```

Shard routing is exact:

```python
if file.startswith("crates/carrick-runtime/src/vcpu_loop/"):
    shard = "vcpu-loop.json"
elif file.startswith("crates/carrick-runtime/src/"):
    shard = "runtime.json"
elif file.startswith("crates/carrick-vmm-hvf/src/"):
    shard = "hvf.json"
else:
    raise LedgerError("unowned abort root")
```

Each row requires `verdict`, `failure_domain`, `rationale`, and
`typed_error` when verdict is `typed_error_debt`. Each shard records an exact
`typed_error_debt_ceiling` equal to its measured debt count; additions fail and
removals require lowering the ceiling in the same change.

- [ ] **Step 4: Make the synthetic suite GREEN**

Run:

```bash
python3 scripts/migrate/test-runtime-aborts.py
```

Expected: PASS.

- [ ] **Step 5: Classify every `vcpu_loop` abort at the leaf**

Bootstrap only the `vcpu-loop` shard to stdout. Current HEAD has exactly 129
calls across `mod.rs` (74), `quiesce.rs` (33), and `executor.rs` (22); treat
those numbers as a reconciliation assertion, not a future ceiling. Review each call independently
across `mod.rs`, `quiesce.rs`, `executor.rs`, `exec.rs`, `signal.rs`,
`continuation.rs`, and `threads.rs`. Do not classify a whole function or file.

Use these rules:

- `carrier_fault`: continuing can publish recycled MM/executor identity,
  violate a committed K1 transaction, or run guest code after carrier authority
  is corrupt. State the corrupt authority explicitly.
- `typed_error_debt`: one guest operation can fail without invalidating the
  carrier's other processes. Name the concrete error type/result path that must
  replace the abort.

Run the checker and independently machine-count both verdicts.

- [ ] **Step 6: Wire the gate**

Add to `lint-domains` immediately after the global-state gate:

```just
python3 scripts/migrate/check-runtime-aborts.py --check
```

The checker may run with only `vcpu-loop.json` during this task if its config
explicitly names the remaining two shards as required-but-pending. It must not
silently ignore those roots once Task 5 lands.

- [ ] **Step 7: Verify and commit**

Run:

```bash
python3 scripts/migrate/test-runtime-aborts.py
python3 scripts/migrate/check-runtime-aborts.py --check
git diff --check
```

Commit:

```bash
git add scripts/migrate/check-runtime-aborts.py \
  scripts/migrate/test-runtime-aborts.py \
  scripts/migrate/runtime-aborts/vcpu-loop.json justfile
git commit -m "chore(runtime): classify vcpu loop aborts"
```

---

## Task 5: Classify the remaining runtime and HVF aborts in parallel

**Files:**
- Create: `scripts/migrate/runtime-aborts/runtime.json`
- Create: `scripts/migrate/runtime-aborts/hvf.json`
- Modify: `scripts/migrate/check-runtime-aborts.py` (remove pending-shard mode)
- Modify: `docs/runtime-abstraction-audit-2026-08-27.md` (record current counts)

**Interfaces:**
- Consumes: Task 4's fixed schema and checker.
- Produces: complete coverage of every raw abort in both configured crates.

- [ ] **Step 1: Dispatch two file-disjoint classification workers**

Worker A owns only `runtime.json`; Worker B owns only `hvf.json`. Both receive
the exact current base commit, schema, classification rules, and command:

```bash
python3 scripts/migrate/check-runtime-aborts.py --check-shard runtime
python3 scripts/migrate/check-runtime-aborts.py --check-shard hvf
```

Each report must state total rows, carrier-fault rows, typed-error-debt rows,
and the rule applied per leaf. Neither worker may edit the checker or the other
shard.

- [ ] **Step 2: Review every worker ledger against actual source**

Reject file-level rationales, generic text such as "invariant violation", a
missing typed error path, or any fingerprint that does not resolve to exactly
one current call. Send findings back to the same Antigravity conversation and
allow at most three review rounds.

- [ ] **Step 3: Remove pending-shard mode and prove full exact coverage**

The final checker configuration must be:

```python
REQUIRED_SHARDS = {"vcpu-loop.json", "runtime.json", "hvf.json"}
```

No pending, ignored, wildcard or unowned roots remain.

- [ ] **Step 4: Record current counts without preserving stale audit numbers**

In the runtime audit append a dated implementation receipt containing the
machine-counted current total and per-verdict/per-shard counts. Preserve 420 as
the historical `28a8678c4` snapshot, not a current assertion.

- [ ] **Step 5: Run the integrated mechanical gate**

Run:

```bash
python3 scripts/migrate/test-runtime-global-state.py
python3 scripts/migrate/check-runtime-global-state.py --check
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  scripts.tests.test_host_authority_transitions
python3 scripts/migrate/test-runtime-aborts.py
python3 scripts/migrate/check-runtime-aborts.py --check
RUSTC_WRAPPER= just fmt-check
RUSTC_WRAPPER= just clippy
RUSTC_WRAPPER= just lint-domains
RUSTC_WRAPPER= just test
git diff --check
```

Expected: every new gate passes. Accept the pre-existing compiler host-authority
positional stop only when it remains `changed=[]`; record it separately.

- [ ] **Step 6: Commit**

```bash
git add scripts/migrate/runtime-aborts/runtime.json \
  scripts/migrate/runtime-aborts/hvf.json \
  scripts/migrate/check-runtime-aborts.py \
  docs/runtime-abstraction-audit-2026-08-27.md
git commit -m "chore(runtime): complete carrier abort ledger"
```

## Self-review

- Spec coverage: decisions, process-global scope, all three host-PID APIs, and
  every raw abort under the two controller roots have named tasks and gates.
- Scope boundary: this plan classifies typed-error debt; it does not claim to
  convert every debt row. Conversion lowers the checked ceilings in later
  vertical slices.
- No duplicate PID scanner: Task 3 extends the compiler-resolved census.
- No stale counts: all current totals are generated during execution.
- Delegation safety: Task 5 shards are file-disjoint; checker/schema ownership
  stays with the director/Task 4.
- Completion means exact source-to-ledger equality and successful synthetic
  red-shape tests, not merely the absence of a grep hit.
