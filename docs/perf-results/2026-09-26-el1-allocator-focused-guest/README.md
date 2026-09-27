# Focused EL1 allocator guest witness

Source: `c33e1d152` (full revision in identity files).
`just test-embed el1_metadata_allocator_grows_and_returns_extents --nocapture`
exits 0 on the exact signed executable recorded in `test-identity.json`.
One positive signed executable invoked; 26 signed. The unentitled negative
control passes. Original and CLI run scopes both have zero remaining processes.

The basic phase checks arbitrary alignment and writes. Growth allocates 10 MiB
beyond the 9 MiB bootstrap: two real grants and returns total 3,145,728 bytes.
Across growth and denial/recovery: four requests, three successful grants, one
denial, three returns, and exactly 5,767,168 bytes both granted and returned.
No timing ratio is claimed from this instrumented test.

This closes the two observed integration defects: maintenance exit routing and
double advance of the HVC completion PC. It proves the focused guest transport
and allocator witness, not the complete allocator contract or memory checkpoint.

Remaining direct allocator requirements: replace ordinary heap backing with
Carrick coherent host mappings; bind aperture ownership and exact return to
carrier VM custody/generation; retain records on failed reset/unmap; prove
concurrent users/pending host work and IRQ protocol; close structural/retention
budgets and private test-control gating. Then install the shared MMU mutation
protocol and elastic user-frame grants for EL1 first-touch. The <0.125
incremental host-exits/page gate remains red. Higher signed promotion, full CI
and workload ratios remain open.
