# Integrated metadata signed gate: first-touch remains red

Source a6ac6935ca96c37947a23749481120bd3933876f; later commit
8acb35b14 adds documentation/evidence only. CLI and all eight invoked signed
executables are frozen and hash verified in receipt.json. This failed run has
an independent manifest because the signed runner publishes normal receipts
only on success.

The gate exits 1 solely on el1_memory_first_touch_stays_in_guest. Forty-one
other EL1 tests and the negative entitlement control pass. Both run-ID cleanup
counts are zero. The 30-round oversubscribed kick test passes in 128.03 seconds.

Both processes preserve zero-fill/private contents at all scales. Total pages
512/2048/8192 incur 621/2150/8294 host exits: first incremental slope 0.9954
versus the unchanged <0.125 ceiling. Actual guest first-touch service remains
unimplemented. Compilation in the separate worker overlapped this gate; printed
CPU/wall diagnostics are not accepted workload timings or speedup evidence.

Public probes, selected LTP and inotify timing steps did not run because the
recipe stopped at the failed embed step. No smoke/full promotion is claimed.
