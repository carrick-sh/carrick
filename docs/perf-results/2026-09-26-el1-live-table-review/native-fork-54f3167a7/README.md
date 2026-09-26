# Matching-image native fork authority

Source checkpoint: `54f3167a7d1929e962788e79b552a63cec03cf04`.
The snapshot-buffer reuse correction is integrated at this revision.

All 12 native-arm64 Docker semantic rows passed: direct, dirty-parent, and
shell/exec launch at scales 1, 8, 32, and 128. Each row requires the exact six
output fields, zero exit status, and no remaining named container. Full commands,
image inspection, fixture hash, and per-row outcomes are in `results.json`;
stdout and stderr are retained separately. No Carrick guest ran concurrently.
These are semantic controls, not workload timing measurements.

The initial preparation selected the current Docker Ubuntu tag's August image
(index `33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517`).
Live inspection found Carrick's cached Ubuntu tag still used April's manifest
`7607b6f97024ef850f1bd6e91a89273beb5973d04432c5b87f15f813d64b9c05`.
The runner was corrected before execution to use that exact manifest. It asserts
arm64 architecture, cache manifest identity, and equality of uncompressed root
filesystem layer digests before running. Neither shared tag was changed.
Earlier different-image receipts must not be used as same-image timing proof.

The fixture SHA-256 is
`1239c755486ab7d1c53cfb0675d22499810457ff0b8067db16945fb9960ced62`.
Integrated CI is still running on `54f3167a7`; signed fork/memory validation,
full promotion, first-touch migration and end-to-end acceptance remain open.
