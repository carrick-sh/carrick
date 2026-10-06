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
  all three retained scanners enforce this boundary.
- Literal built-in inclusions retain physical paths and production closure.
  Rust source literals in arbitrary macro inputs are rejected, including DSL,
  nested groups and attribute tokens. Parsed test-only inclusion reachability
  closes before unbound production seeding; genuine production references win.
  Built-in data-only `include_bytes!` may compute its path: it cannot emit Rust.
- Sensitive import renames/re-exports are rejected. The vocabulary covers
  authority operations/types, raw termination and environment access; alias
  taint closes transitively. Plain renames have no allowlist escape. Environment
  and termination imports must use their explicit canonical paths.
- Custom attributes require an entry in
  `scripts/migrate/authority-attribute-allowlist.json`. Each entry names the
  exact macro/helper and its audited provider, with a rationale for why
  expansion cannot introduce authority or raw termination. Literal metadata
  is accepted; executable arguments also require the census's closed argument
  grammar. `error` permits field/constant projections and zero-argument
  get/as_secs/as_millis/display adapters. `arg` permits constant/variant paths.
  Blocks, sensitive names and other calls remain errors even with an entry.
  With production globs, audited attributes/derives must use absolute provider
  paths (`::serde::Serialize`, for example). Derive helpers require a matching
  audited derive on the parsed item; opaque helpers and glob imports are
  rejected. This proof avoids resolving names imported by a glob.
  Derive macros also require an audited provider; standard compiler derives
  remain built-in. Audited names cannot be rebound by imports or modules.
  Protected callbacks in literal metadata are rejected. To add an
  entry, audit the locked implementation, document its expansion, extend the
  closed grammar only if needed, and add positive and rejection witnesses.
  Unrecognized syntax must be rewritten; it is never resolved by guessing.

Documentation-only macro templates may forward built-in doc values, whose
compiler expansion cannot change a module path, cfg scope or runtime body.
Other attribute templates are unsupported. Opaque imports must be rewritten as
explicit parsed imports (or generated constants), preserving platform types.

The schema-absent historical PR base alone uses legacy ledger-to-owner
conversion. Working source always uses the restricted dialect; a base with
`authority-debt-ceilings.json` reads that schema directly and cannot enter the
legacy path. Historical undercounting can only tighten the ratchet. Remove
this one-time bootstrap in the next inventory-retirement PR after #51 lands.
