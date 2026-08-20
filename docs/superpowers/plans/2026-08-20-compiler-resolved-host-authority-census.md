# Compiler-Resolved Host-Authority Census Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the rejected lexical Rust scanner with a compiler-resolved,
fail-closed census of reviewed host-facility uses in Carrick product targets.

**Architecture:** Pinned Clippy `disallowed-methods` diagnostics provide
canonical operation and production-cfg truth. A Python tool orchestrates a
checked build matrix and validates Cargo JSON plus structured review records;
it never parses Rust to resolve names. Forced warnings override source
expectations, while a narrow escape-hatch syntax gate covers mechanisms outside
the method catalog.

**Tech Stack:** Rust/Clippy 1.96, Cargo JSON diagnostics, Python 3 standard
library (`json`, `subprocess`, `tomllib`), existing `just` and Semgrep gates.

**Spec:** `docs/superpowers/specs/2026-08-20-compiler-resolved-host-authority-census-design.md`

## Global Constraints

- Host containment is the primary security boundary; intra-guest isolation is
  a co-equal Linux-conformance obligation.
- The collector consumes compiler diagnostics only; it must not recover Rust
  call, cfg, import, or module semantics from source text.
- `--force-warn clippy::disallowed_methods` is mandatory for authoritative
  census runs and must pierce every ordinary source expectation.
- A partial build-matrix run may compare its own profiles but must not refresh,
  delete, or bless canonical rows belonging to unexecuted profiles.
- Product diagnostics may be `forbidden_semantic`, `declared_backing`, or
  `declared_substrate`; `legacy_unreachable` is invalid for compiled product
  rows.
- Guest waitability, exit status, process-record reclamation, or CLI-visible
  liveness derived from a host wait/liveness call is `forbidden_semantic`.
- Do not claim cross-platform completeness until every declared platform slice
  has run with its pinned toolchain in its real check environment.
- Preserve unrelated worktree changes and use `apply_patch` for edits.
- No guest run is required until the parent Phase 0 plan reaches its signed
  artifact tasks.

---

### Task 1: Freeze the compiler-diagnostic contract

**Files:**
- Create: `scripts/tests/fixtures/host-authority-census/Cargo.toml`
- Create: `scripts/tests/fixtures/host-authority-census/clippy.toml`
- Create: `scripts/tests/fixtures/host-authority-census/src/lib.rs`
- Create: `scripts/tests/fixtures/host-authority-census/macros/Cargo.toml`
- Create: `scripts/tests/fixtures/host-authority-census/macros/src/lib.rs`
- Create: `scripts/tests/test_host_authority_clippy_contract.py`

**Interfaces:**
- Consumes: pinned `cargo clippy` and `--force-warn` behavior.
- Produces: `capture_fixture(extra_args: list[str]) -> list[dict[str, object]]`
  in the test module and a deterministic fixture diagnostic set used by Task 2.

- [ ] **Step 1: Create the fixture workspace**

The fixture library must contain these seven resolved uses and no others:

```rust
use std::process::id as imported_id;
pub use std::fs::read as reexported_read;

pub fn direct() -> u32 { std::process::id() }
pub fn imported() -> u32 { imported_id() }
pub fn reexported() { let _ = reexported_read("/fixture"); }
pub fn function_item() { let call = libc::waitpid; let _ = call; }
pub fn local_macro() { local_call!(std::thread::yield_now()); }
pub fn dependency_macro() { fixture_macros::host_call!(std::fs::metadata("/fixture")); }
pub fn expected() -> u32 {
    #[expect(clippy::disallowed_methods, reason = "HA-FIXTURE-EXPECTED")]
    std::process::id()
}
```

Define `local_call!` as an expression macro and the dependency macro in the
fixture's `macros` member. Configure exactly these canonical methods in the
fixture `clippy.toml`: `std::process::id`, `std::fs::read`,
`std::fs::metadata`, `std::thread::yield_now`, and `libc::waitpid`.

- [ ] **Step 2: Write the red compiler-contract test**

Run Cargo with:

```python
command = [
    "cargo", "clippy", "--manifest-path", str(FIXTURE / "Cargo.toml"),
    "--lib", "--message-format=json", "--",
    "--force-warn", "clippy::disallowed_methods",
]
```

Parse stdout one JSON object per line. Select `reason.code.code ==
"clippy::disallowed_methods"`, require a primary span, and assert seven
diagnostics: three `std::process::id` sites plus one each for the other four
fixture uses, including the expectation-covered site. The reexport must report
at its callsite, not its `pub use` declaration. Assert the function-item and
macro diagnostics report expansion/callsite spans rather than disappearing.

- [ ] **Step 3: Run the contract red**

Run:

```bash
python3 scripts/tests/test_host_authority_clippy_contract.py
```

Expected: FAIL until the fixture and exact JSON assertions agree with pinned
Clippy. An import alias, broad expectation, or macro may not reduce the count.

- [ ] **Step 4: Correct the fixture without weakening assertions**

Adjust only valid Rust fixture mechanics and the expected canonical diagnostic
fields. Do not remove a semantic shape to make the count pass. Store no golden
absolute paths or target-directory paths.

- [ ] **Step 5: Verify and commit**

Run:

```bash
python3 scripts/tests/test_host_authority_clippy_contract.py
git diff --check
```

Expected: PASS and a clean diff check.

Commit:

```bash
git add scripts/tests/fixtures/host-authority-census \
  scripts/tests/test_host_authority_clippy_contract.py
git commit -m "test: freeze compiler authority diagnostics"
```

---

### Task 2: Normalize diagnostics and enforce exact reviews

**Files:**
- Replace: `scripts/migrate/check-host-authority-transitions.py`
- Replace: `scripts/tests/test_host_authority_transitions.py`
- Create: `scripts/tests/fixtures/host-authority-census/messages.jsonl`

**Interfaces:**
- Consumes: Cargo JSON objects with Clippy diagnostics.
- Produces:
  `normalize_messages(messages, profile_id, root) -> list[dict[str, object]]`,
  `merge_profiles(profile_rows) -> list[dict[str, object]]`,
  `validate(actual, expected, executed_profiles, required_profiles) -> None`,
  and `refresh(actual, expected, complete) -> list[dict[str, object]]`.

- [ ] **Step 1: Record path-independent diagnostic fixtures**

Transform Task 1's seven diagnostics into `messages.jsonl`, replacing the
fixture root with `ROOT/` and retaining only fields the normalizer consumes:
`reason.code`, `reason.message`, `reason.spans`, and child notes containing the
configured catalog reason. Include three non-Clippy Cargo messages to prove
they are ignored.

- [ ] **Step 2: Write failing normalization tests**

Tests must assert:

```python
self.assertEqual(row["operation"], "std::process::id")
self.assertEqual(row["profiles"], ["macos-hvf-default"])
self.assertEqual(row["source"]["file"], "scripts/tests/fixtures/host-authority-census/src/lib.rs")
self.assertIn("line", row["source"])
self.assertIn("column", row["source"])
```

Add failures for unknown operation text, missing/duplicate primary spans,
outside-root paths, malformed JSON, duplicate diagnostic identity, and two
different operations resolving to the same review ID.

- [ ] **Step 3: Write failing review/refresh tests**

Use this exact review shape:

```json
{
  "review_id": "HA-000001",
  "operation": "std::process::id",
  "source": {"file": "crates/example/src/lib.rs", "line": 10, "column": 5},
  "expansion": null,
  "profiles": ["macos-hvf-default"],
  "classification": "forbidden_semantic",
  "evidence": {"authority": "guest_answer", "resource": "guest-visible process identity"},
  "rationale": "The carrier PID would otherwise answer guest getpid semantics."
}
```

Require new rows to refresh as `classification: "unreviewed"` with empty
evidence/rationale; changed operation/source/expansion must not inherit a
review; removed rows fail validation; partial refresh raises
`InventoryError`; compiled product rows reject `legacy_unreachable`; empty,
extra-field, generic, or schema-mismatched evidence fails.

- [ ] **Step 4: Implement JSON-only normalization and validation**

Delete the token lexer, cfg parser, import resolver, Rust source traversal, and
standalone-target reachability code. Extract canonical operation from the
backticked Clippy message `use of a disallowed method `<path>`` and cross-check
it against the catalog reason child. Normalize macro expansion to the outermost
workspace callsite and retain the compiler primary span separately.

Identity is canonical JSON of `operation`, `source`, and `expansion`.
Profiles are merged only after identity equality. Reviews are preserved by the
same identity and never by prose, kind, or source text.

- [ ] **Step 5: Verify and commit**

Run:

```bash
python3 scripts/tests/test_host_authority_transitions.py
python3 -m py_compile scripts/migrate/check-host-authority-transitions.py \
  scripts/tests/test_host_authority_transitions.py
git diff --check
```

Expected: all pass.

Commit:

```bash
git add scripts/migrate/check-host-authority-transitions.py \
  scripts/tests/test_host_authority_transitions.py \
  scripts/tests/fixtures/host-authority-census/messages.jsonl
git commit -m "refactor: consume compiler authority diagnostics"
```

---

### Task 3: Declare and enforce the product build matrix

**Files:**
- Create: `scripts/migrate/host-authority-build-matrix.json`
- Modify: `scripts/migrate/check-host-authority-transitions.py`
- Modify: `scripts/tests/test_host_authority_transitions.py`

**Interfaces:**
- Consumes: matrix profiles and Task 2 normalization.
- Produces:
  `load_matrix(path) -> Matrix`,
  `run_profile(profile, runner=subprocess.run) -> list[dict[str, object]]`,
  CLI `--profiles`, `--check`, and `--refresh-candidate`.

- [ ] **Step 1: Add the canonical matrix schema**

The checked JSON must contain tool requirements and profile objects:

```json
{
  "schema": 1,
  "toolchain": {"rustc_release": "1.96.0", "clippy_release": "0.1.96"},
  "required_profiles": [
    "macos-cli-default", "macos-runtime-default", "macos-hvf-default",
    "linux-cli", "linux-runtime", "freebsd-cli", "freebsd-runtime",
    "netbsd-cli", "netbsd-runtime"
  ],
  "profiles": [
    {
      "id": "macos-cli-default",
      "host": "macos",
      "command": ["cargo", "clippy", "-p", "carrick-cli", "--bin", "carrick", "--message-format=json", "--", "--force-warn", "clippy::disallowed_methods"]
    },
    {
      "id": "macos-runtime-default",
      "host": "macos",
      "command": ["cargo", "clippy", "-p", "carrick-runtime", "--lib", "--message-format=json", "--", "--force-warn", "clippy::disallowed_methods"]
    },
    {
      "id": "macos-hvf-default",
      "host": "macos",
      "command": ["cargo", "clippy", "-p", "carrick-vmm-hvf", "--lib", "--message-format=json", "--", "--force-warn", "clippy::disallowed_methods"]
    }
  ]
}
```

Add the six non-macOS profiles with the exact `_platform_features` arguments
from `justfile`; each invokes `carrick-cli --bin carrick` or
`carrick-runtime --lib` under its platform feature set. Host mismatch makes a
profile unavailable, not successful.

- [ ] **Step 2: Write red matrix/orchestrator tests**

With a fake runner, assert exact command argv, `cwd`, clean JSON stdout,
nonzero-exit failure, stderr preservation in the error, tool-version mismatch,
duplicate/missing profile IDs, host mismatch, and rejection of commands that
omit both `--force-warn` and `--message-format=json`.

Assert `--refresh-candidate` requires the complete `required_profiles` set,
while `--check --profiles macos-*` compares only macOS rows without deleting
or rewriting other profile rows.

- [ ] **Step 3: Implement the orchestrator**

Use argument arrays only—never `shell=True`. Set a task-specific target dir per
profile under `target/host-authority-census/<profile-id>` so concurrent ordinary
build artifacts cannot contaminate compiler messages. Verify `rustc -V` and
`cargo clippy -V` before the first profile.

The normal local `--check` default selects profiles whose `host` matches the
current host. It reports all unexecuted required profiles as pending and never
describes the result as complete.

- [ ] **Step 4: Verify and commit**

Run:

```bash
python3 scripts/tests/test_host_authority_transitions.py
python3 scripts/migrate/check-host-authority-transitions.py --help
git diff --check
```

Expected: PASS; `--help` documents partial versus complete semantics.

Commit:

```bash
git add scripts/migrate/host-authority-build-matrix.json \
  scripts/migrate/check-host-authority-transitions.py \
  scripts/tests/test_host_authority_transitions.py
git commit -m "build: declare authority census matrix"
```

---

### Task 4: Install the watched catalog and migrate the macOS inventory

**Files:**
- Modify: `clippy.toml`
- Replace: `scripts/migrate/host-authority-transition-inventory.json`
- Modify: `scripts/tests/test_host_authority_transitions.py`

**Interfaces:**
- Consumes: Tasks 1-3 compiler collector and matrix.
- Produces: the reviewed canonical macOS/HVF slice and a catalog consistency
  contract.

- [ ] **Step 1: Add red catalog coverage tests**

Parse `clippy.toml` with `tomllib` and require unique stable catalog IDs in each
reason. Assert the catalog contains every operation from the rejected
inventory plus `libc::waitpid`, `std::fs::OpenOptions::open`,
`libc::syscall`, and dynamic lookup functions present on the current host.
Assert no entry sets `allow-invalid = true` for the canonical macOS slice.

- [ ] **Step 2: Add the compiler-resolved catalog**

Add `disallowed-methods` entries for the existing canonical operations and the
breaker omissions. Use reasons of the form:

```toml
{ path = "libc::waitpid", reason = "HA-CATALOG-PROCESS-WAITPID: host wait state requires reviewed authority" }
```

Do not enable the restriction lint in ordinary builds; the census command
activates it with `--force-warn`.

- [ ] **Step 3: Capture the macOS profiles red**

Run:

```bash
python3 scripts/migrate/check-host-authority-transitions.py \
  --profiles macos-cli-default,macos-runtime-default,macos-hvf-default \
  --refresh-candidate /tmp/host-authority-candidate.json
```

Expected: FAIL because a partial profile set cannot bless the canonical
inventory, but `/tmp/host-authority-candidate.json` is emitted with every row
`unreviewed`. Confirm it contains `libc::waitpid` rows and the liveness sites
named in the breaker review.

- [ ] **Step 4: Review every macOS row**

Promote the candidate into the checked inventory only after source review.
Assign stable IDs monotonically. Apply the strict classification rules from
the spec, including:

- `container.rs` liveness feeding `Running`/`Exited`: `forbidden_semantic`;
- namespace supervisor liveness affecting guest wait/reclamation:
  `forbidden_semantic`;
- runtime/HVF waits feeding guest child-exit readiness:
  `forbidden_semantic`;
- permit-reaper calls that act solely on authenticated carrier ownership:
  `declared_substrate`;
- capability-rooted host filesystem bytes/metadata: `declared_backing`.

Every rationale names one concrete answer, target, backing object, or carrier
resource. Do not copy the rejected inventory mechanically; use it only to find
source context.

- [ ] **Step 5: Add invariant tests and verify**

Tests must require `libc::waitpid` presence, the named liveness classifications,
zero `legacy_unreachable`, zero `unreviewed`, unique review IDs, and exact
profile membership for macOS rows. Run:

```bash
python3 scripts/tests/test_host_authority_transitions.py
python3 scripts/migrate/check-host-authority-transitions.py \
  --check --profiles macos-cli-default,macos-runtime-default,macos-hvf-default
git diff --check
```

Expected: PASS with an explicit report that six non-macOS profiles are pending.

- [ ] **Step 6: Commit**

```bash
git add clippy.toml \
  scripts/migrate/host-authority-transition-inventory.json \
  scripts/tests/test_host_authority_transitions.py
git commit -m "security: census resolved host authority calls"
```

---

### Task 5: Deny catalog escape hatches and wire the gate

**Files:**
- Create: `.semgrep/host-authority-escape-hatches.yml`
- Create: `scripts/migrate/check-host-authority-escape-hatches.py`
- Create: `scripts/tools/host-authority-escape-syntax/Cargo.toml`
- Create: `scripts/tools/host-authority-escape-syntax/Cargo.lock`
- Create: `scripts/tools/host-authority-escape-syntax/src/{lib.rs,main.rs}`
- Create: `scripts/tools/host-authority-escape-syntax/tests/scanner.rs`
- Create under `scripts/tests/fixtures/host-authority-escape-syntax/`:
  rustc/rustfmt-valid reject and safe fixtures
- Create: `scripts/tests/test_host_authority_escape_hatches.py`
- Modify: `scripts/lint-domains.sh`
- Modify: `justfile`
- Modify: `docs/host-facility-boundary.md`
- Modify: `docs/superpowers/plans/2026-08-19-trustworthy-authority-baseline.md`

**Interfaces:**
- Consumes: compiler census and catalog.
- Produces: local fail-closed escape-hatch lint and honest Phase 0 docs.

- [ ] **Step 1: Write red escape-hatch fixtures**

Use temporary Rust files and the real deterministic lint launcher. Require
findings for:
`libc::syscall`, `dlsym`/`dlopen`, `asm!`/`global_asm!`, and a local `extern
"C"` declaration of `waitpid`, `kill`, or filesystem/process-control host APIs.
Require no finding for comments, strings, the checked boundary fixture, or
ordinary safe Rust calls already covered by Clippy.

- [ ] **Step 2: Add narrow Semgrep deny rules**

Rules must identify unmistakable escape-hatch constructs only. Because Semgrep
1.166 does not reliably inspect Rust macro token trees or preserve extern
ABI/link-name context, supplement it with a small checked standalone Rust
helper using exact-pinned `proc_macro2` tokenization. It recursively inspects
every token group; comments are absent and string/char/raw/byte/C literals stay
atomic. `syn` is permitted only for correct `link_name` literal decoding. The
helper emits deterministic JSON/text. A Python wrapper runs it locked/offline
in an isolated repository target, validates the JSON, applies exact
`PurePosixPath` allowlists, and propagates build/scan status; Python performs no
Rust lexing or parsing. The token helper recognizes only direct watched libc
paths and imports/reexports, assembly invocations/import aliases, extern ABI
declarations, and watched `link_name` literals. It must not recover Rust name,
cfg, module, or reachability semantics. Exclusions are exact reviewed boundary
files, never suffix matches or directory globs. Every diagnostic names the
compiler catalog or typed capability facade as the required replacement.

- [ ] **Step 3: Wire deterministic local checks**

Extend `scripts/lint-domains.sh` to run both checked Semgrep configs through the
existing deterministic environment. Change `just lint-domains` to run:

```just
lint-domains:
    ./scripts/lint-domains.sh
    python3 scripts/migrate/check-host-authority-transitions.py --check
```

The census reports pending non-host profiles but fails on local drift. Do not
run Docker or a guest.

- [ ] **Step 4: Make documentation honest**

Document the three distinct facts:

1. Clippy compiler diagnostics establish the configured callsite census for
   executed product profiles.
2. Structured reviews and humans classify those calls; the validator does not
   prove semantic truth.
3. Typed capability enforcement and raw-host-API denial outside the facade are
   Phase 1 work.

Replace the obsolete Phase 0 Task 2 lexical-parser instructions with a pointer
to this plan and record the breaker commits as rejected evidence, not closure.

- [ ] **Step 5: Verify and commit**

Run:

```bash
python3 scripts/tests/test_host_authority_escape_hatches.py
python3 scripts/tests/test_host_authority_clippy_contract.py
python3 scripts/tests/test_host_authority_transitions.py
just lint-domains
just fmt-check
git diff --check
```

Expected: all pass; the census explicitly reports non-local profiles pending.

Commit:

```bash
git add .semgrep/host-authority-escape-hatches.yml \
  scripts/tests/test_host_authority_escape_hatches.py \
  scripts/lint-domains.sh justfile docs/host-facility-boundary.md \
  docs/superpowers/plans/2026-08-19-trustworthy-authority-baseline.md
git commit -m "security: enforce compiler authority census"
```

---

### Task 6: Review and rejoin the Phase 0 controller

**Files:**
- Modify: `.superpowers/sdd/2026-08-19-trustworthy-authority-baseline/progress.md` (ignored controller ledger only)

**Interfaces:**
- Consumes: reviewed Tasks 1-5.
- Produces: an accepted replacement for original Task 2 and an exact handoff to
  original Task 3.

- [ ] **Step 1: Run focused replacement gates**

```bash
python3 scripts/tests/test_host_authority_clippy_contract.py
python3 scripts/tests/test_host_authority_transitions.py
python3 scripts/tests/test_host_authority_escape_hatches.py
just lint-domains
```

- [ ] **Step 2: Run the ordinary compiler gates**

```bash
just fmt-check
just clippy
```

Expected: PASS. This is not yet the parent plan's full `just ci` task.

- [ ] **Step 3: Perform a fresh whole-task review**

Review from `7c08e8bbd` through the replacement head. The reviewer must verify
that no rejected lexical parser remains authoritative, forced warnings pierce
expectations, the local matrix slice is exact, partial runs cannot bless the
canonical inventory, current wait/liveness sites are correctly classified,
and escape hatches fail closed.

- [ ] **Step 4: Update the controller ledger**

Record exact commits, test exits, local profile counts, pending remote profiles,
review findings/fix rounds, and the statement:

```text
Original Task 2 lexical implementation rejected at breaker; compiler-resolved replacement accepted. Phase 0 local macOS census is enforced. Cross-platform matrix slices remain pending until their real-host CI receipts exist.
```

- [ ] **Step 5: Rejoin original Task 3**

Continue at “Make every syscall authority declaration explicit” using the
existing restricted `syscall!` macro ruling. Do not mark the wider security,
conformance, or performance goal complete.
