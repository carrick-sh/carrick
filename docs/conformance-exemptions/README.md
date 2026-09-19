# Conformance Exemptions

This directory contains append-only, reviewed conformance exemption receipts for changes that have been proven not to alter guest-visible behavior or operational complexity.

## When exemptions apply

Only changes proven not to alter guest-visible behavior or cost qualify:
- byte-identical moves / refactorings across repository boundaries;
- comments, docstrings, and documentation;
- mechanical generated-inventory rebinding; or
- host-only code outside the guest execution path.

An exemption may **never** claim that performance or operational complexity is "out of scope" for a guest-visible change.

## Schema

Exemption files must be named `*.toml` in this directory and follow schema `carrick.conformance-exemption.v1`:

```toml
schema = "carrick.conformance-exemption.v1"
base = "1111111111111111111111111111111111111111"
head = "2222222222222222222222222222222222222222"
paths = ["exact/repository/path.rs"]
contracts = ["kernel.futex.contention"]
rationale = "Byte-preserving ownership move; contract behavior and work units are unchanged."
```

## Constraints

The ratchet enforces:
1. `schema` must be `"carrick.conformance-exemption.v1"`.
2. `base` and `head` must be full 40-character hexadecimal Git commit object IDs (abbreviated hashes are rejected).
3. `paths` must list exact repository-relative paths present in the diff (globs and directories are rejected).
4. `contracts` must name registered contract IDs from `conformance-contracts/contracts/`.
5. `rationale` must be at least 40 characters explaining why the change does not alter guest-visible semantics or work invariants. Phrases such as "performance out of scope" are rejected.
