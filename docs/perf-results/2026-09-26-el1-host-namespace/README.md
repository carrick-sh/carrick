# Independent namespace work comparison

Director comparison of base 5d612ffb5 production logic and candidate 3b7715b26. The three candidate source hashes were checked against that final candidate. The same namespace witness and component counters ran on both arms; cold assertions were deferred until all rows printed, preserving the assertions. Cargo exited 101 on base and 0 on candidate. Both runs completed their workloads; no guest or Docker execution was involved. The integration checkout was restored byte-for-byte afterward.

At scale 128, backend directory opens changed from 381 to 0 for same-directory rename and 510 to 0 for cross-directory rename. Counted metadata changed from 1152 to 1024 for both. Dentry opens were 0 in both warm arms. Unlink regressed from 384 to 512 counted metadata calls (3 to 4 per operation), with zero opens in both arms. The candidate remains unintegrated pending removal of that duplicate work and semantic review. No timing improvement or full Stage 2a acceptance is claimed.

The worker-authored red-baseline.log reported different dentry and metadata counts and is not accepted as an executed same-instrument baseline. These full process transcripts and hashes supersede that receipt. total_metadata is backend_stats plus parent_fstats; it does not establish that every possible host syscall across all namespace fixtures is instrumented. Full native controls and signed differential gates remain open.

compare.py is the exact director execution script, with frozen full source files retained under target/el1-completion/namespace-independent. It temporarily replaces only three tracked VFS files and restores them in finally; it asserts a clean checkout and matching base production files before running. Reproduction requires the named worker revision and the same witness shape. Do not execute against an actively edited worker.

## Source integration

Final candidate `b3a6ea73f` was integrated as `4cca6aba1`, `f4d7508e7`,
and `0d8bf00cd`. It reuses admitted entry metadata to remove the intermediate
unlink regression. Independent final-candidate checks passed: 253 parallel
VFS tests, 38 serial tests, Clippy, and contract registry. The integrated
structural witness passes at all four scales. At 128 operations rename uses
0 backend opens and 1024 counted metadata calls; unlink uses 0 opens and 384
counted metadata calls, matching original unlink cost. Inventory reconciliation
updated positions and capture provenance with all 588 host-authority rows
preserved and no semantic inventory changes.

This is source integration only. Full domain lint, signed differential,
openat work, native controls, workload timing and Stage 2a closure remain open.

Full `just lint-domains` passes on `f664e7e02` after reviewing and registering the test-only parent-fstat counter. Signed differential and workload acceptance remain open.
