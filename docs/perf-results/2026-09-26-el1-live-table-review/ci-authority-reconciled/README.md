# Integrated authority-reconciled CI

The existing `RUSTC_WRAPPER= just ci` process completed with exit 0 on
`3914aa43763188319f7b3b8079ead7fc20481c87`. The log reports 6,180 passed tests,
zero failures and 12 ignored tests across 101 result groups. Only controller
and plan documentation changed during this run. The raw log and receipt are
preserved here. This closes host CI for the two resolver fixes and the
position-only authority reconciliation. It does not qualify the in-progress
fault-entry implementation, signed guest execution or workload ratios.
