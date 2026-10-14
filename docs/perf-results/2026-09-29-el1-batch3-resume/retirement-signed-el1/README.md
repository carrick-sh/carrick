# Signed EL1 regression after terminal retirement correction

Source f0036b2a5 (documentation after 64573c8f6; same production code).
The normal `scripts/test-signed.sh carrick-embed el1_` selection passed all
50 unique executions across nine executables. The unentitled negative
control passed, and both runner cleanup and an independent process census
found zero scoped processes, including the kick fixture CPU burners.

Each of the nine current executable hashes was independently compared with
the completed receipt, then its exact bytes copied under its SHA256 to
`target/el1-resume-b3/retirement-signed-el1/tested-executables/` before any
subsequent signing step. The previously accepted Go CLI hash remained
unchanged; embed executions have their own identities in signed-artifacts.jsonl.

The parked-thread crash-register witness is included: its name contains
`el1_`. The earlier 26079e466 gate receipt also records this test as passed;
the previous scratch-ledger claim that its qualification was missing was
a lookup error, not a real gate gap. This new receipt independently proves
it on the corrected source.

This is signed regression evidence, not full batch-3 acceptance. Notification
work observations, remaining producer/service/restore proofs, windowcoherence
population, full probe/conformance qualification and controlled cost gates
remain open. Next work is the scoped notification structural observation,
not another repetition of this same green suite.
