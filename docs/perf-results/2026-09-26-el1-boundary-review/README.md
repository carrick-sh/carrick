# Personality-boundary draft: director rejection evidence

The initial worker draft is not accepted. The director froze its built
`check-personality-boundary` executable, hashed it, and ran six isolated
manifest/source fixtures. `results.json` records the hash, outputs and exit
codes. This is a draft-binary review, not an attested final source build or
signed execution receipt.

| Fixture | Expected | Observed |
|---|---|---|
| Caller-supplied result | Pass | Pass |
| Direct `carrick-abi` dependency | Reject | Reject |
| `-110` in `#[cfg(not(test))]` production module | Reject | Pass |
| `-110` in production `mod tests` from `tests.rs` | Reject | Pass |
| `-110` inside a production `macro_rules!` expansion | Reject | Pass |
| Path dependency with a missing manifest | Reject | Pass |

The positive and direct-negative controls show the checker was invoked. The
four false passes block integration. Required fixes include syntax-aware
non-test reachability, actual module/dependency traversal, a macro policy, and
red/green fixtures. The reviewed dependency closure must not silently stop at
registry/git dependencies or missing paths. These checks are a known-pattern
architecture rule; they cannot prove absence of all encoded Linux semantics.

## Resolved-graph candidate review

The second-round candidate also false-passes two hermetic Cargo fixtures:

- `custom_lib_path`: `[lib] path = "kernel.rs"` contains `pub const RESULT: i64 = -110;`. The checker returns success with **zero scanned files**.
- `optional_transitive`: the substrate has optional `bridge`; bridge depends on `carrick-abi`. The checker returns success with an empty shipped dependency closure.

Both fixtures have local-only dependency paths and an offline-generated lockfile.
Results and the exact candidate executable SHA-256 are in `round2-results.json`.
The executable was copied from the worker's build directory during review; this
is a draft-checker blackbox result, not attested source acceptance. Fixtures and
the frozen executable remain under `target/el1-completion/boundary-review-round2`.
The implementation also retries failed locked/offline metadata without those
flags; acceptance requires preserving the locked graph rather than resolving
a new graph after a failure.
