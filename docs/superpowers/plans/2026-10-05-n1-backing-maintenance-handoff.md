# N1 pending-brk backing maintenance handoff

Status: typed production correction implemented; fresh signed qualification pending.
The tested source is `77b7d5e7151e142b95dacbca376aebbab607ced0`, on exact
batch-5 main `51bfe67f4`. Do not rebase to batch 6 or integrate helper PRs
14/11/21/16 as part of this repair. The director approved this correction via
mailbox on 2026-10-05. Fork/root arena repair is separately owned by `n1-fork`
on `work/n1-fork`, based on `1dfba1500`; coordinate before editing those paths.

## Evidence and first reproduction

The full exact-artifact receipt is in
`docs/perf-results/2026-10-04-n1-batch5-gate.md`. Full CI, rustdoc, five Loom
models, signed hello/negative control and 10/10 uninstrumented copyout pass.
The anonymous fixture aborts at heap contraction after the partial-retirement
residency repair gets it past its former SIGSEGV. Five fork/root cases still
fail earlier than main's completing workloads. No review-ready verdict.

Retained artifacts: `target/n1g2/batch5-77b7d5e71/`.
`diagnostic/brkprogress.raw:1706-1708` names syscall 214, address
`0x4000002000`, length 4096, then copyout PREPARE phase 4/detail 4 (Gate).
`diagnostic/brk.log` reproduces the abort with one owner-bind control,
errors/drops zero and scoped cleanup zero. The second trace is diagnostic
ordering evidence, not acceptance or a timing comparison. No guest remains.

The actual VM-free witness is retained locally at:

- `/tmp/n1g2-brk-maintenance-witness.patch`
- SHA-256 `260cebd99035c3ab8d36b7721804d3277b2c45e1dc7f3e023d65f794517fec34`
- `/tmp/n1g2-brk-maintenance-red.log`

Apply the patch to the clean checkpoint and run:

```sh
cargo test -p carrick-el1 --lib personality::mm_portal::tests::pending_brk_scrub_must_not_wait_for_its_own_gate -- --exact
```

The semantic red is the final assertion:
`pending brk scrub selected its own transaction wait: Some(Owner(... cause:
Gate, revision: 2))`. An earlier fixture-setup error (using an EL1 root holder
for a host proposal) was corrected; the retained log is the real self-wait.
The witness uses a real notified root, exact host `brk` retirement request,
nonidentity heap backing, invalidation before scrub, and the actual hardware
PREPARE admission function. The preselected ordinary UserWrite makes the
failure explicit; the eventual test must exercise the production maintenance
binding, while ordinary UserWrite must remain refused under that same gate.
The failing witness was restored out of the regular test file after capture;
it is not ignored or treated as green. Preserve the original red evidence.

## Production seam and approved shape

`dispatch/mem/brk.rs` owns `BreakMove.pending`, creates the host reservation
proposal, invalidates the tail, marks it unmapped, then calls `zero_backing`.
The call occurs before `complete_delegated` releases the pending operation.
`carrick-aarch64/src/engine.rs::zero_backing` routes admitted roots through
`write_owner_bytes`, which creates an ordinary UserWrite PREPARE. Hardware
`mm_portal/production.rs::admit_service_root` correctly suspends that request
on the raised Gate. Even after that preamble, ordinary authorization refuses
pending edits and ordinary translation requires accessible user descriptors.
Changing only one of these checks would leave a second failure or permit an
unauthorized write. The heap scrub must retain its own operation authority.

Implement a typed owner-authorized backing-maintenance operation bound to the
exact pending reservation and physical custody. Its API must not represent
ordinary user-copy admission or a wait for its own Gate. Authenticate the
carrier, MM/incarnation, pending request fields/sequence, operation/range and
live physical owner generation; retain that authority through invalidation,
scrub and completion. A user VA is not an IPA. A recycled root/VA or a
neighbor's retained frame must not satisfy the request. Fork/COW backing must
be privately owned before zeroing, not silently scrubbed through a shared
physical alias. Keep the root/editor unlocked across any physical supply or
scheduler suspension; such a wait must own the exact continuation.

Do not open/lower the gate to make the scrub work, move zeroing before
invalidation, permit a generic privileged UserWrite, use legacy host memory
fallback for an admitted root, or mark a failed scrub complete. Keep the
existing invalidation-before-scrub ordering and rollback/failure semantics.
Do not increase transfer bounds, alter the guest fixture, add retries, change
concurrency, or weaken semantic/work budgets.

Before production edits, extend the VM-free witness to the new typed seam:
valid pending retirement succeeds; ordinary UserWrite remains excluded;
wrong MM/incarnation/request generation/sequence/range and stale physical
custody refuse before writes; a reused VA and fork-shared frame cannot be
scrubbed; adjacent bytes survive; regrowth is zero. Assert bounded descriptor
and physical-custody work independent of unrelated mappings. Existing Loom
models are required but do not substitute for this mechanism witness.

After the correction: focused VM-free tests, clean inventory reconciliation,
full `just ci`, `just test-loom`, native Linux fixture publication, then a new
signed artifact and the anonymous case plus exact 10/10 copyout and hello
under one exclusive lease. Compare all six regressions by failure mode.
Record new provenance and cleanup; the 77b7d5e71 receipts cannot transfer.
Only post review-ready after the remaining functional regressions close.

## Implemented owner operation

`PortalBackingMaintenance` carries the complete pending Retire proposal and
admitted incarnation through a distinct service entry. The owner borrows its
paused editor, authenticates the actual heap contraction, and walks the live
invalid leaf. It uses the existing physical COW grant pool and slot-scoped
copy aliases to zero a private replacement, then repoints while preserving
inaccessibility. It never writes the predecessor, even when a live fork peer
shares it. Missing subtrees advance the cursor without page-by-page service
calls. Host physical supply and exact inventory settlement happen after the
service releases both root/editor and driving-vCPU loans. Generic
`zero_backing` refuses admitted roots; only the pending brk binding can issue
this operation.

The saved witness reproduced its Gate assertion on the integrated fork tree.
Its green form additionally checks corrupt identities/request fields, the
ordinary UserWrite Gate, aliased replacement refusal, a live COW peer's bytes,
adjacent bytes, stale physical generation rejection, regrowth/VA reuse, and a
96-word descriptor budget with hundreds of unrelated terminal leaves. The
278 EL1 tests, 134 ABI tests and eight focused brk tests passed; workspace
clippy passed. Clean-tree inventory capture, full CI/Loom and exact signed
qualification follow this source checkpoint. No signed or N1 acceptance is
claimed by these VM-free results.

## Signed checkpoint after integration

The exact `e1435e4e0` gate is recorded in
`docs/perf-results/2026-10-05-n1-maintenance-gate.md`. Full CI and five Loom
tests passed. The anonymous guest now reports its complete zero/regrowth
assertions `ok=true`, then fails at the separate captured-thread clear-child-tid
check. All six comparison tests remain red. Copyout is 8/10: two exact-grant
supply refusals; hello and entitlement negative control pass. All 21 scoped
cleanup records are zero and the one exclusive gate has ended.

VMA and ptrace each live-qualified `OWNERFORKREFUSAL1` at errno 22/stage 3
(table pool/live words), with closed-child controls, no script errors, no
bound expiry and successful consumer receipts. Forward these lines to n1-fork.
Keep the retained artifact for driver diagnosis of clear-child-tid identity
and exact grant refusal. This is a committed handoff, not N1 acceptance.
