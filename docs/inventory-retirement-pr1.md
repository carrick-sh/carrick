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
