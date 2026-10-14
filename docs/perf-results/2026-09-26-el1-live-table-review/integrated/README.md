# Live-table source integration

Integrated source: `0f67bd38b`, including worker product candidate `22323a343`
and director corrections `878d3a69e`, `988c0aedc`, `df1b13634`, `33eafc56e`.
Their integrated hashes are `832e41f17`, `3ffbbc2c3`, `cbd6b313c`, `0f67bd38b`.
The worker final `55bdfc220` adds inventory-only changes; inventories were
instead reconciled on this combined source, preserving 588 authority rows.

The formerly failing runtime snapshot control now passes on this exact source:
`RUST_TEST_THREADS=1 RUSTC_WRAPPER= cargo test -p carrick-runtime --lib
--features conformance-metrics stage1_snapshot_observes_live_leaf_after_guest_publication
-- --nocapture`. One test executed; exit zero. No guest ran.

Reviewed inventory reconciliation changes positions and capture provenance
only. Full CI and signed promotion are next; this is source integration of the
live-authority prerequisite, not completion of memory migration. First-touch
remains structurally red until actual EL1 fault handling and elastic grants.

## Integrated allocation correction: full host gate

`RUSTC_WRAPPER= just ci` on product checkpoint `85a17114b` exited zero.
The only commit made during execution was `22c42b64d`, containing native
oracle receipts and controller notes; no product or test source changed.
All 101 test result groups pass (6,180 passing tests, zero failures, 12 existing
ignores). Formatting, workspace Clippy, domain checks, dependency policy,
feature-matrix/compile checks, warning-free docs and host integration completed.
The authority census still explicitly marks non-macOS CLI/runtime profiles
pending; this is not cross-platform execution acceptance.

Full transcript: `ci-85a17114b.log`, SHA-256
`7296b3a436ca06dcf999d70541e3f8f4c4799cda080399eb6482a9ab32f7b108`.
Signed fork validation started separately at source `22c42b64d` with run ID
`el1-live-fork-20260926-22c42b64d`. It is not yet accepted. First-touch, signed
memory validation, full promotion and all later migration checkpoints remain open.
