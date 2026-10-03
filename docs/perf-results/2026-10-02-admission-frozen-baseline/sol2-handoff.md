# EL1 admission continuation: REVIEW-READY, 2026-10-02

Branch work/s3-t3b, clean HEAD 8f0e14fafcfd210a545cd780e8eda0be05f97eab.
No active build or guest. No push, main merge, Docker, agents, stash,
node-count increase, timeout increase, budget relaxation or retries.

Director superseded permanent cede/demotion: it is NOT implemented.
Admission remains irreversible per MM incarnation. Capacity unavailable
returns Linux ENOMEM consistently; raw brk preserves old break. Initial
admission secures the existing reserve before publication. See accepted
plan /Volumes/CaseSensitive/carrick/docs/superpowers/plans/2026-10-02-el1-step2-memory-completion.md.

Product commits since fda854282:
282a78f99 initial/child admission reserve and consistent capacity refusal.
efb0792a6 lazy new root mappings over acknowledged retired descriptors.
5ff6aa380 charge/reserve every host root proposal, including brk/mremap.
791833a68 root-copyout access prevalidation; mailbox generation removed
from backing request only (runtime claim/response checks retained).
777578460 exact current-MM alias + physical owner generation required for
local grant predecessors; retain authenticated outside lease fragments.
Inventories reconciled/reviewed: 7cbedb33a, 956d74060, 7a4ee99e3, 8f0e14faf.

Reader root cause and red-first:
/tmp/s3t3-sol2-readers-prepare.dtrace: 6,717 copyout declines matched invalid
mailbox generation=0 in backing service. Removing generation fixed this
refusal, but readers still failed. Subsequent phase-22 completed trace
/tmp/s3t3-sol2-readers-lease.dtrace found no registered aliases, only local
rows with globally live physical owners. Such rows do not establish current
MM ownership. Exact alias+generation authentication fixes original signed
reader (3.61s), and full-suite reader is green. Red/green unit logs:
copyout-validation-{red,green}, copyout-generation-{red,green},
partial-grant-{red,green}, mm-alias-{red,green} (all /tmp/s3t3-sol2- prefix).
The partial-fragment candidate alone did not close readers; do not claim it did.

FINAL ACCEPTANCE receipts:
/tmp/s3t3-sol2-final-acceptance.json and .log (mechanical audit PASS).
/tmp/s3t3-sol2-final-embed-acceptance.json records all 11 tested identities.
/tmp/s3t3-sol2-final-el1.log: 78 passed, four allowed main failures only:
concurrent_vma_ops, fork_cow_resolves_in_guest, ptrace_traceclone, spawn_slope.
map_fixed_over_cow_pages PASSED this run. Anonymous reservations GREEN.
Raw harness exit 1 reflects allowed failures; negative control passed.
All 30 kick bursts and both kick stress tests passed. Both scoped cleanup
checks zero. No successful all-green harness receipt claimed.

Final CLI artifact (same bytes across all nine CLI runs):
SHA256 705eba95cfbc70c6f66ad023ff0ce205a9b6e3036658bf0c5f27757935c9163c
CDHash 6788ebd0e5636669f20643d788f2c0a3f073f43f
LC_UUID E2FCDC36-751D-3461-A60A-E742A8F56D53
Hypervisor entitlement and __dof_carrick verified. Source clean at HEAD.
Build log /tmp/s3t3-sol2-final-cli-build.log.

/tmp/s3t3-sol2-final-{cpython,node,go}.json record commands, run IDs,
identity before/after, completion, cleanup. Raw streams in target/<run-id>.
CPython: 208 tests run, two skips, SUCCESS. Node worker-message-port: 26/26.
Go: BUILD_OK exactly once. All reservations/threads/sigmask ON.
Small-stack final paired OFF and FIVE ON runs: all 49 tests/one skip,
various_ops_small_stack explicitly completes each. All same artifact;
ON durations 3.738/3.642/3.704/3.646/3.664s. OFF 3.696s.
/tmp/s3t3-sol2-final-smallstack-{off,on-1,on-2,on-3,on-4,on-5}.json
and final-smallstack.log. No separate timeout-specific fix is claimed:
prior timeout did not reproduce in paired attribution or final five runs.

HOST GATES after final product fixes (all exit zero):
/tmp/s3t3-sol2-copyout-test-kernel.log: 2,375 kernel tests + semantics pass.
copyout-test.log: just test passes.
copyout-hvf-lib.log: explicit serial HVF lib 696 pass, three ignored.
copyout-clippy.log: workspace all-target clippy passes.
copyout-reconcile-reviewed.log: clean reconciliation zero rebindings.
copyout-lint.log: lint-domains passes. Host-authority gate qualifies macOS
subset; other host profiles remain explicitly pending (existing gate scope).
K1 count -1 review: removed documentation line, not a removed operation.

Director signed lane may resume after SIGNED-DONE notification. Final review
ready notification uses ref 8f0e14faf. Only director landing/review remains.
