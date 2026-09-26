# Live-table revision review evidence

This is director evidence against an in-flight, uncommitted review-1 draft in
`el1-memory-core`, based on `6a538d49f`. It is not a verdict on a later worker
commit. `snapshot-source.sha256` identifies the exact copied MMU source.
The frozen source and standalone Cargo project remain at
`target/el1-completion/live-review-repro` in the integration worktree.

Command: `RUSTC_WRAPPER= cargo test --offline --manifest-path target/el1-completion/live-review-repro/Cargo.toml --test snapshot`

Compilation succeeded; the test exited 101 with one failure. A resident,
atomically allocated backing is made unavailable through its resolver without
freeing memory. `snapshot_image` correctly reports an error. `clone` then
silently returns a live manager, retaining shared authority rather than yielding
an independent owned image. The reproduced failure is the final assertion in
`snapshot-fallback-repro.rs`. No guest, Docker, or invalid-pointer execution was
used. The worker tree was not modified by this check.

Revalidate against the final revision and require explicit failure at the
snapshot boundary; a silent shared-state fallback does not satisfy fork-image
isolation. Existing allocation and work budgets remain unchanged.
