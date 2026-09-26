# Live-table source integration

Integrated source: `d51e1915a`, including worker product candidate `22323a343`
and director corrections `878d3a69e`, `988c0aedc`, `df1b13634`, `33eafc56e`.
Their integrated hashes are `580b6dea6`, `8ed5d0945`, `cda616a40`, `d51e1915a`.
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
