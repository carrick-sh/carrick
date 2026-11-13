# x86 CPL0: an idle-peer `install_space` fatal under a sibling munmap during a held COW

Seen in red runs of the #1482 P0-3 witness on 7b0ea15cf plus the witness
(runs r7-red-18, r7-red-27): "unexpected idle peer physical doorbell 0xcc" at
`carrick_x86_cpl0::native_execution::schedule` (native_execution.rs:55,
`install_space(...).unwrap_or_else(fatal_boot)`). In those runs the carrier also hit
the P0-3 failure. It has not been seen on the fixed head (10+ green runs), so it may
be a downstream effect of P0-3 rather than its own defect. It needs a look:
`install_space` refusing (for example while a host exclusion holds the space gate)
should be "not now", never fatal.
