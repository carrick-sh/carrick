# Inventory retirement audit: PR 1

Authoritative section copied from `/home/carrick/dev/batch-tools/inventory-retirement-audit.md`, audited at `51bfe67f40f879c46ae506612c37e76f4867d5c7`.

### PR 1 — remove positions and ambient inventory fingerprints from landing (M)

**Remove:** committed macOS capture J07; positional rows in J04/J08/J14/J15; contextual-source fingerprints in global/abort ledgers; T06/T07/T14/T15/T16 once their count consumers are replaced; `reconcile-inventories`, `test-reconcile-exit-status`, `remote-recapture`, recapture CLI/module dispatch, positional writer tests and abort-row merge branches. Update active instructions at [AGENTS.md:87](/home/carrick/dev/wt-inv-audit/AGENTS.md:87), [AGENTS.md:428](/home/carrick/dev/wt-inv-audit/AGENTS.md:428), [AGENTS.md:455](/home/carrick/dev/wt-inv-audit/AGENTS.md:455). Historical file:line citations in design documents remain historical references, not gates.

**Replace with:** one position-free `AuthorityDebtCeilings` representation. Count real production API/symbol cohorts directly; exclude comments and test/definition-only rows. Preserve per-category raw locks, K1 debt, forbidden host semantics, fatal typed-error debt and residual lanes. Retain structural SysV/MM/task rules, raw-abort zero, catalog and profile completeness. Continue live compiler-resolved host discovery, but consume diagnostics ephemerally and compare aggregates/approved boundaries rather than persisted spans, capture hashes or rationale locations. Do not require a separate clean-commit archive/recapture merely to lint working source.

Implement closed family assignment: an unknown authority API/owner cohort fails instead of disappearing from counts. Compare ceiling definitions with the actual PR base; reject increases, removed nonzero counters and unrecognized families. Tighten unjustified existing slack where the live census confirms the same cohort. Keep guest-state/raw-abort zero rules unconditional, including the stronger global-state checks currently behind an optional flag.

**Red-first witnesses:**

- Insert blank lines and relocate an unchanged function: gate passes, counts unchanged, no tracked inventory/receipt changes and no remote recapture required.
- Add one raw lock acquisition, legacy file-authority access or forbidden host operation: corresponding count/boundary fails.
- Raise its ceiling in the same patch: base/head ratchet still fails.
- Inject the existing Linux breaker, then alias/macro/cfg variants: live resolved gate fails; stored macOS evidence cannot satisfy it.
- Add raw abort or ambient guest-state construction: zero rule fails.
- Rename/move a rule owner: negative fixtures remain active; missing owner discovery fails closed.

**Exit condition:** no source line/column/byte offset or ambient inventory fingerprint is part of accepted landing identity; no reconcile or remote-recapture command remains in the landing flow. Error diagnostics may still show source locations.


## Restricted source census dialect (owner decision 2026-10-05)

The working-source census is a syntax contract, not a Rust name resolver or
macro expander. Unsupported syntax is a hard error with file, line and column;
it never supplies test exclusion or silently promotes a source file.

- Module paths must be literal `#[path = "..."]` selectors. Inline module
  children resolve against the inline-module directory. Duplicate paths and
  conditional `cfg_attr(..., path = ...)` selectors are rejected.
  External modules must be declared in parsed Rust, outside macro inputs.
  Macro expansion can change their directory even when the input parses as
  Rust. Literal inline metadata modules remain usable; dynamic module names
  and external selections in templates, invocations and DSL tokens fail.
- Test exclusion requires parsed built-in `#[test]` or a provable built-in
  `#[cfg(...)]` test/test-support predicate. Imports/renames that rebind `test`,
  qualified test attributes, conditional test attributes, and opaque macro
  test/path attributes are rejected wherever production is possible. Globs
  cannot prove a built-in test attribute. A parsed cfg(test) ancestor supplies
  independent proof: imports in its discarded body cannot exclude any item
  outside it. External modules carry this proof from the strict Rust census
  into retained discovery; scanners never infer it from a filename. Rust and
  all three retained scanners consume this Rust verdict. Unresolved production
  `macro_use` extern-crate imports are rejected before test exclusion.
- Literal built-in inclusions retain physical paths and production closure.
  Rust source literals in arbitrary macro inputs are rejected, including DSL,
  nested groups and attribute tokens. Parsed test-only inclusion reachability
  closes before unbound production seeding; genuine production references win.
  Built-in data-only `include_bytes!` may compute its path: it cannot emit Rust.
- Sensitive import renames/re-exports are rejected. The vocabulary covers
  authority operations/types, raw termination and environment access; alias
  taint closes transitively. Plain renames have no allowlist escape. Environment
  and termination imports must use their explicit canonical paths. Sensitive
  namespace `self` and glob imports, and unresolved unqualified protected
  calls, are rejected. Protected free functions may appear only as direct
  canonical path calls or through an exact, unrenamed plain item import.
  Parenthesized callees, generic function references, function-pointer
  bindings and captures are rejected. Direct receiver calls remain counted;
  data declarations with the same spelling do not become authority operations.
  Macro input containing protected operations requires a complete audited
  grammar in `scripts/migrate/authority-macro-allowlist.json`. Executable
  expressions and bodies are visited and counted; unparsed input and
  protected function values fail. Local macro audits bind exact definition
  hashes. Typed guest syscall selectors are data under their audited defining
  implementation; their executable handler bodies are separately counted.
- Custom attributes require an entry in
  `scripts/migrate/authority-attribute-allowlist.json`. Each entry names the
  exact macro/helper and its audited provider, with a rationale for why
  expansion cannot introduce authority or raw termination. Literal metadata
  does not by itself prove safe expansion; executable arguments also require
  the census's closed argument
  grammar. `error` permits field/constant projections and zero-argument
  get/as_secs/as_millis/display adapters. `arg` permits constant/variant paths.
  Blocks, sensitive names and other calls remain errors even with an entry.
  With production globs, audited attributes/derives must use absolute provider
  paths (`::serde::Serialize`, for example). Derive helpers require a matching
  audited derive on the parsed item; opaque helpers and glob imports are
  rejected. This proof avoids resolving names imported by a glob.
  Derive macros also require an audited provider; standard compiler derives
  require provable bindings too. Imports, aliases, extern-crate `macro_use`
  and ambiguous globs cannot replace those compiler bindings. Use an absolute
  compiler provider under a production glob (for example `::core::clone::Clone`).
  Canonical standard trait imports remain permitted, including anonymous
  `Hash as _` imports that create no macro binding. Audited names cannot be
  rebound by imports or modules, including `{self}` imports whose bound name
  is the preceding path component. External derives require their canonical
  crate path even when no production glob is present.
  Protected callbacks in literal metadata are rejected. To add an
  entry, audit the locked implementation, document its expansion, extend the
  closed grammar only if needed, and add positive and rejection witnesses.
  Unrecognized syntax must be rewritten; it is never resolved by guessing.

The clap `env` helper option generates `Arg::env`, whose locked
`clap_builder` implementation calls `std::env::var_os` while constructing the
command. Its audit therefore carries an operation and exact declared
owner/key map, rather than treating it as inert metadata. The existing CLI
configuration and conformance-harness keys are admitted at their host
configuration owners. `CARRICK_RUN_ID` helper metadata is rejected everywhere;
that key remains an explicit read at the LaunchContext boundary. Binding an
audited source file into a different logical module does not transfer its
metadata permission. Owners include the full lexical path: inline modules,
enclosing functions and implementations. A nested `RunArgs` namesake does not
inherit the permission of `carrick_cli::args::RunArgs`.

## Retained scanner verdicts

Rust is the single dialect and scope authority. `authority-census` emits JSON
with dialect rejections, each source file's production status and SHA-256,
and item/statement exclusion ranges in UTF-8 byte offsets. Standalone probe
profile scope is recorded separately and cannot grant a test exemption to a
retained zero rule. It also records
compiled census/policy input hashes. A stale executable cannot emit a verdict
for changed policy inputs. The retained scanners have no test-attribute,
configuration-predicate or macro-scope classifiers: they mask Rust-excluded
ranges while preserving positions, then check only their own patterns.
The verdict also supplies the canonical call heads and byte ranges for exact
plain item imports. Retained lexers apply those Rust-resolved heads verbatim;
they never resolve bindings or classify scope independently.

Standalone use requires a fresh verdict:

```sh
cargo run --locked -p carrick-xtask -- authority-census > target/authority-census.json
python3 scripts/migrate/check-runtime-aborts.py --census-verdict target/authority-census.json
python3 scripts/migrate/check-runtime-global-state.py --census-verdict target/authority-census.json
python3 scripts/migrate/check-dispatch-lock-authority.py --census-verdict target/authority-census.json
```

A nonempty `rejections` array fails every scanner. Missing verdicts, changed
policy inputs, changed source bytes, changed parent/module declarations, new
or removed files, and a different tree root also fail closed. Source-level
scanner APIs require the same verdict and validate its tree, not just the
scanned child's bytes. Tree scanners validate before and after discovery and
hash each input when masking it. `authority-debt` passes the in-memory census
verdict through a scoped temporary file, so no cached artifact grants an
exemption. Python fixtures
obtain fresh verdicts from the compiled Rust census; the gate already builds
that binary before executing them.

Documentation-only macro templates may forward built-in doc values, whose
compiler expansion cannot change a module path, cfg scope or runtime body.
Other attribute templates are unsupported. Opaque imports must be rewritten as
explicit parsed imports (or generated constants), preserving platform types.

The schema-absent historical PR base alone uses legacy ledger-to-owner
conversion. Working source always uses the restricted dialect; a base with
`authority-debt-ceilings.json` reads that schema directly and cannot enter the
legacy path. The private bootstrap emits an explicitly tagged historical Rust
verdict; standalone working-source scanners reject that tag. It still uses the
same pattern scanners and contains no Python scope-classification fallback.
Historical undercounting can only tighten the ratchet. Remove
this one-time bootstrap in the next inventory-retirement PR after #51 lands.

## Census undercount repair (director ruling 2026-10-06)

The single Rust classifier exposes one production operation that the retired
Python classifier omitted. The director authorized exactly this correction;
no existing ceiling was increased and no runtime behavior changed.

| Counter | Actual base source | Why Python missed it |
| --- | --- | --- |
| `global_config_debug / global:env_var_os / carrick_runtime::vcpu_loop::ThreadRuntimeState<E>::new::CARRICK_TRACE_TRAPS / shared = 1` | `crates/carrick-runtime/src/vcpu_loop/mod.rs:1046`: `trace: std::env::var_os("CARRICK_TRACE_TRAPS").is_some(),` | Attributes on preceding `#[cfg(test)]` struct initializer fields leaked into this production sibling. Rust excludes each field independently. |

The entire source file was identical at the accepted Round 7 head
`2dc25b175` and actual base
`8233b5488b92b406bce8bbe4ee495c0e09b166a5`; SHA-256
`6e366be31a1683d49333d250cec2afe744d8e4160823a7b977855c332955ef12`.
This is an owned ratchet item. Reading `CARRICK_TRACE_TRAPS` in production
runtime outside the LaunchContext boundary remains a defect for the
director-owned follow-up; adding its census counter does not approve that
runtime design.


## Production SysV helper contract repair

The Rust production mask exposed a mistaken required-owner assertion for
`with_sysv_process_mut`. History and blame confirm that no production lock
responsibility disappeared: commit `9dad96736adcfb55443a0019709d95e9d9c07d35`
introduced this helper already under built-in `#[cfg(test)]`.
`f95c9d049989657912d8d2f3788cfb518633b654` moved the same discipline into
`IpcView`; `c2228d660c` later required every helper spelling without excluding
that test-only definition.

| Contract | Production owners and evidence | Correction |
| --- | --- | --- |
| SysV process and namespace lock discipline | `IpcView::lock_sysv_process` at `sysv.rs:2030` acquires the process mutex and creates `SysvProcessGuard`; mutable shmat, remap, exit, fork and shmdt paths still call it at lines 2053, 2136, 2152, 2187 and 2441. `SysvProcessGuard::namespace_permit` exclusively borrows that guard before `SysvNamespacePermit::lock_paired`. | Require the four production helpers `with_state`, `with_state_mut`, `lock_sysv_process`, `with_sysv_process`, plus the paired `lock_paired` owner. Do not require the test-only mutation helper as a production owner; any production definition still receives its exact visibility and cross-module checks. |

Rust-proof fixtures cover the test-only shape, deletion of a required
production helper, and unauthorized visibility on a production mutation
helper. No runtime code or ceiling changes accompany this contract correction.
