# Integrated fault-entry CI

`RUSTC_WRAPPER= just ci` completed with exit zero on
`084c9a2725e34ecc58269ebcbb13bf73a90505f0` with a clean source checkout.
The Rust result groups total 6,188 passed, zero failed and 12 ignored across
101 groups. The complete log and its SHA-256 are retained alongside this file.

This covers the integrated fault-entry implementation, its test-only lint
corrections, and reconciled authority positions. The authority census still
explicitly reports six non-macOS profiles pending; local CI success does not
close those profiles. This is host validation, not broader signed execution,
in-guest first-touch acceptance, or workload performance acceptance.
