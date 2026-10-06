# N1 fork control-capacity retirement

The retained `fa98b9f9c` `case_elf_exec_errno` fails its second fork with
`stage-1 extension arena IPA 0x9a00400000 is still held by the root-slot pool`.
This is a physical-capacity lifecycle failure, independent of file-table lease
and clone-TID behavior. The stack is still not landable against main.

## Retained production evidence

Evidence root:
`/Volumes/carrick-build/evidence/n1-cm/main-match-fa98b9f9c/`.

- `root-slot-error3.core`, `root-slot-error3-lldb.txt` and
  `root-slot-error3-values.json`: LLDB stopped at the actual failed allocation
  branch, `sparse_materialization.rs:858`, in `prepare_owner_fork_builder`.
- The ring contains 130 records with no decoding errors. Child PID 2's exit
  publication completes before the next fork, parent MM 3 to child MM 6.
- The next control request is `0x9a00400000`, a 2 MiB arena. Its earlier
  physical record 131, owner 18, remains mapped with zero pins and neither
  retirement requested nor owner retired. The native pool still holds slot 2,
  while the source lease's logical allocator has offered that slot again.
- The first `root-slot-collision2.core` stops before allocation, where slot 2
  is free. It is a pre-allocation snapshot, not the refusal snapshot. Attempt
  1 missed the branch entirely; neither is substituted for error3 evidence.
- All three diagnostic runs have scoped cleanup receipts with zero remaining
  processes. They used the retained signed executable and matching symbols,
  without rebuilding or conferring a new acceptance verdict.

## Cause and correction

Owner Fork allocates both a child root and private control capacity from the
child's table-arena source. Physical preparation publishes both. The new
`Stage1Authority` observes the root and retains that source, but previously
never recorded the control arena in its physical retirement ledger. A host
page-table manager never links this control arena, so discovery of reachable
table arenas cannot recover the missing obligation.

The root's exact retirement proof released the source lease's logical root
and extension slots while control backing remained live. Exec predecessor
cleanup also cannot infer this obligation from the global-frame directory:
these fixed structural owners are deliberately absent from that directory.

Child observer assembly now consumes the exact authenticated Fork completion
and records its already-published control arena in the existing authority's
capacity ledger. Exit and exec retire that arena through the exact MM's
`MmArenaPublisher` before minting the root proof. A pin blocks that proof;
the logical source therefore cannot recycle still-live capacity. No host VMA
projection, alternative allocator or fallback mapping was added.

## Red-first native witness

`owner_fork_control_capacity_retires_before_root_proof_and_reuse` and
`owner_fork_control_capacity_retires_before_exec_root_proof_and_reuse` exercise
the same observer constructor used by the production engine, native pooled
backing, exact structural owners, MM publisher and root-proof path. No HVF VM
is created.

Both witnesses first pin control backing. Retirement must refuse a root
proof and keep the root and control unavailable. After unpinning, exact
retirement makes both child slots reusable while an unrelated peer's physical
record and slot stay live. Retained owner references do not delay pool reuse.

Under `main-match-20261005/`, `owner-control-red.log` records the original
one-test semantic failure. `owner-control-red-pair.log` reverses only the new
control-retention call: both exit and exec fail with
`a pinned fork control arena must prevent logical root reuse`. The restored
positive result is recorded separately. No timeout, budget or retry changed.

Restored verification under the gate lease passes: seven owner-fork tests
(including both new witnesses), 101 retirement tests, 118 AArch64 tests,
contract validation, fmt-check and workspace all-target clippy. Receipts are
in `main-match-20261005/owner-control-verify/`. The independent diff review
found no code blockers; it did not qualify signed execution or landing parity.

Contract: `kernel.fork.stage1-image`. This witness proves physical lifetime
and exact-scope reuse, not guest instruction execution, hardware invalidation
or a runtime ratio. New signed results require a director-published exact
bundle, forced image rebuild and artifact identities.

## Other evidence remains open

The retained TLS fault has an exact MM 5/request 19 mailbox response,
`FRAME_GRANT_ERR_DENIED`, at `0x600041bbf8`; older descriptor fields are not a
current refusal verdict. The additional `owner-fault-retained.trace` fired
pointwise submission/withdrawal facts but did not close its external-test
consumer. It required scoped cleanup and is not a qualified complete trace.

Main's six excluded signed reds are director-reported. Their exact first
failure lines have been requested: main `65098ea0e` and this stack both lack
the `PTRACE_SETOPTIONS` dispatcher arm, so the current errno 38 at that call
must not be classified as a new regression from a workload-only assumption.
All other main-pass failures remain blocking; no signed repair pass is claimed.
