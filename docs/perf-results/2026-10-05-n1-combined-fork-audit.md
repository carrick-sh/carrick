# Combined N1 fork and reserved file-content audit

Audited source `4d374b5e7471dae437893c50f6742b3197198dd3` starts
from pushed handoff `7f6a2f757` on integrated N1 `56bf8c0ca`. It merges
exact file-mmap fix `3c5113bda` without rebasing. `08739b162` preserves
the original authored commit; `4d374b5e7` forwards its reserved-content
capability through the production runtime split view.

Evidence root: `/Volumes/carrick-build/evidence/n1-cm/main-match-20261005/`.
`combined-stack-audit.tsv` records fourteen guarantees: nine kept, five
ported, zero dropped. The original ten CM guarantees and both file-content
boundaries have fresh controls in `combined-audit-4d374b5e7/controls.tsv`: all
21 negative commands produce behavioral failures; all 27 restored tests pass.
Supplemental `base-controls-4d374b5e7/controls.tsv` re-proves integrated exit
participant revision publication and order 4 wait admission/completion: four
behavioral negative commands and nine restored passing tests. Every temporary
source edit is restored byte-for-byte. Compiler failures and zero-test runs
are not counted. No registered timing or signed work claim is inferred.

The kept/ported classification covers this worker's combined guarantees.
`combined-fix-commit-inventory.txt` retains the larger historical fix inventory.
Other owners' entire integrated history is not claimed individually reversed;
file-table lease and clone-TID remain their owners' scope.

A fresh read-only review identifies an open native file-content consumer
defect in the imported fix: `write_existing_backing_unchecked` still calls
the legacy-only host COW selector, and its subsequent unchecked translated
write also enters a legacy-only host raw-copy path. Both reject an admitted
N1 owner. The routed kernel and runtime split witnesses replace that native
consumer and therefore cannot establish end-to-end file-mmap success.
A native consumer red witness and owner-compatible correction remain open.

The exact earlier signed `ea0b4c26b` result remains five fork failures at
`HVPatch COW compound IPA 0x2e00000000 has no exact inventory coverage`.
The restored extent, vvar, custody and identity ports have fresh VM-free
proof only. Main-pass parity, copyout reuse and inotify churn require a new
exact director bundle and the baseline per-test list from main `16df3d6f9`.
No signed pass, landing readiness, budget relaxation or retry closure is claimed.
