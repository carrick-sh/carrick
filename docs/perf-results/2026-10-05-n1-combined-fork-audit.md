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

The fresh read-only review found two native consumer refusals hidden by the
original model witnesses: both host COW selection and unchecked translated
copy required legacy admission. A real native consumer control on `fa98b9f9c`
reproduces both refusals. The correction passes a borrowed exact reserved-write
proof through the existing engine/backend interfaces and recomputes the live
stage-1 IPA after COW. The original split-loop witness now drives the actual
native engine/copier with kernel-minted inventory. Four independent controls
cover COW admission, raw-copy admission, non-identity output and producer
selection; see `native-content-controls-v1/` and `native-content-controls-v2/`.
The native inventory negative also exposed an unarmed shared-private write;
that path now refuses without an exclusive private claim. A fifth behavioral
control reproduces backend count one with kernel count two; both populations
now have to establish sole ownership under the existing frame-registry order. Positive live guest
COW and file-map signed confirmation require a new exact bundle.

## Exact signed result on fa98b9f9c

Director-authorized signed acceptance and five fork tests plus three refusal
traces ran on clean `fa98b9f9c5a965544725a77f5bb5832faa6951c2`, with its
published bundle and forced EL1 image rebuild. The embed image SHA-256 is
`caffed3e16027905be3ae4488b0c9398e6f5d58a403dfe8b2aea682584a684b0`;
the CLI image is
`181e2ed1e4442d80480a5e0633db95b21993993cfedd0a96771ed5197cc5a856`.
Image-byte matches, artifact signatures and cleanup receipts are retained.

Against the director's main `65098ea0e` baseline: 44 pass rows, 78 unexpected
failure rows, five known fork reds failing earlier than main, one matching
anonymous budget red, and one fresh-executable test not executed after the
first test's watchdog. Generic shards abort early, so later individual probes
lack results. This stack is **not landable**. These counts classify test rows,
not every guest subprobe or every baseline test. Exact generic-shard signatures
were not retained before the case runner re-signed package executables; raw
logs survive, and this provenance gap remains explicit.

All five focused fork workloads fail. VMA completes the parent's eight rounds
but loses the child; fixed-over-COW fails parent-wait-f in round zero; ptrace
options return errno 38; spawn slope and focused fork-COW raise SIGSEGV 11 before
workload output. Main completes all five workloads and fails only serving/exit
budgets. The earlier `0x2e00000000` inventory error is absent. Each refusal trace
closes two child witnesses with zero refusals, two guest results, one completed
libtest witness, zero errors and no bound expiry. Trace command exit zero is
probe closure, not a workload pass; no refusal/check/arena line fired.

Results and qualified trace rows:
`/Volumes/carrick-build/evidence/n1-cm/fork-fa98b9f9c/results.tsv`.
Broad per-test comparison and acceptance receipt:
`/Volumes/carrick-build/evidence/n1-cm/main-match-fa98b9f9c/`.

A separate LLDB diagnostic on the retained signed fork-COW artifact catches a
write fault in musl `__copy_tls`, PC `0x29c604`, FAR `0x600041bbf8`, MM 5/TID 17,
with an invalid L2 descriptor. The coherent event ring has 264 records and no
decoding errors. An earlier capture faults at the same instruction in MM 2,
before fork. This identifies a broader TLS/anonymous first-touch failure;
its root cause is not yet proved. It was reported to the director before any
anonymous-fault edits. Generic probes also expose a separate root-slot collision
at `0x9a00400000`. Fresh-executable diagnostics retain a carrier core repeatedly
waiting for already-exited PID 31; a copyout/reaping diagnosis remains a
hypothesis. File-table lease and clone-TID code remain unchanged.
