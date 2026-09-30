# EL1 migration: user-requested local consolidation and pause

The user requested a clean stopping point and fast-forward to main, then
explicitly limited consolidation to the current implementation/controller and
incorporated foundations. Older unfinished branches are preserved separately.
Nothing was pushed. This is consolidation of unfinished work, not acceptance.

## Integrated source

Main fast-forwarded from f304f8415 to 4d3484cc2, including merge c90ce118e:
- Adapter 0c8204e11: memory foundations, IPC routing, descriptor/copyout/COW
  caller work, sparse publication f5a50259b, and the hardware service witness.
- Controller/lifecycle 66b1a21d4: slot-liveness, pgrp/ICMP fixes, authenticated
  deferred handback and notification work, terminal-population correction.
- Ancestry confirms the COW, descriptor, reservation, elastic-return, IPC host,
  object and wait foundations, plus slot-live/pgrp/ICMP branches are included.

The merge combines generation-authenticated handback with IPC operation-token
retention through cancellation. Host IPC wake callbacks now carry captured
RecordRef instead of rereading an incarnation after publishing ownership.
One wait-unlink callback runs before queue publication for both futex and IPC.
Fixtures now explicitly publish their executor driver, as production does.

## Verification and limits

- Scheduler: 80 passed, including pending-object cancellation through handback.
- EL1: 116 passed. Runtime IPC adapter: 2 passed.
- Affected all-target Clippy passed; formatting hook passed.
- Signed service rebuilt and executed FROM MAIN source 4d3484cc2 under run ID
  el1-main-stop-20260929-a. One test passed: unpublished MM refusal leaves the
  live leaf unchanged, followed by actual EL1 ForkArm and exact host settlement.
  Host writes remain fenced. Unentitled control passed, both cleanup scopes 0.
  See main-stop-signed.log and main-stop-signed-artifacts.jsonl for executable
  SHA-256/CDHash/LC_UUID/entitlement/DOF identities. This final documentation
  commit does not change product or test source from that checked revision.
- This is one isolated root, with test-retained root backing. It does NOT prove
  two-live-MM isolation, full production COW/backing retirement, TLB workload
  semantics, complete descriptor admission, pause removal or checkpoint closure.
- lint-domains is RED: 17 IPC abort sites lack reviewed classifications. The
  inventory reconciler also refuses a retired FileTable::install lock row and
  changed K1 mapping/description/table/lifecycle classifications. Position-only
  updates and a 595-row compiler capture were retained; no blanket re-blessing.
  See integration-inventories.log and main-stop-lint.log. Full CI and full signed
  checkpoint/workload acceptance were NOT run or claimed for this consolidation.

## Preserved outside this consolidation

- work/cp2-ownership-tests at 45fa94124: deliberately red ownership witnesses.
- work/cp3-ipc-fixture at fd27e748d: rejected fixture.
- work/rt-sigsuspend-parallel-flake at 5011caffa: unverified WIP.
- agy/el1-inotify at 7eb9a6853 and its existing uncommitted files: untouched.

## Resume

Start from main and docs/superpowers/plans/2026-09-26-el1-completion.md.
First resolve the explicit inventory review gaps without weakening the gates.
Then continue the grouped remaining writer conversions and backed/two-MM signed
integration. Production descriptor admission remains disabled. Anonymous policy
and lifecycle ownership, pause removal, batch-3/IPC acceptance, namespace cost,
remaining descriptors/IPC/signals, names/page cache and process lifecycle remain
open. X86 stays deferred by the user's instruction. Goal and hourly monitor are
paused at the user's requested stopping point.
