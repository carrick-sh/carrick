# N1 exact-grant refusal attribution (in progress)

The diagnostic source checkpoint is `cf80ca810`. No production correction
was present during attribution. The deterministic witness
`concurrent_transfer_waits_for_exact_uncommitted_physical_grant` prepares one
real unpublished transfer grant, then requests the same page while that
physical owner remains live and has no committed residency. The contender
must retain completion authority, not decline exact supply or allocate a
second frame.

The witness fails on the integrated tree and on exact `77b7d5e71`, with the
same assertion: `a live unpublished predecessor must own a completion wait,
not decline exact supply`. Baseline source is the detached worktree
`/private/tmp/n1g2-grant-base`; only the same appended test was applied.
Two baseline executions fail identically. This establishes a pre-existing
missing in-flight-publication state, not semantics introduced by either
`42e4070a4` maintenance or `71bd58268` table resolution. The newer binary
exposes the gap more readily in this sample; scheduling attribution to one
change is not established and is not a correctness fix.

A fixed, interleaved ten-pair retained-artifact diagnostic ran under an
exclusive lease with the same copyout guest SHA-256
`d925c73ed2993e4714274566d6be38134d380f62e5b2487996cb25e678323a3b`.
All twenty captures have owner-bind controls, zero errors/bound expiry,
successful consumer receipts and scoped cleanup zero. No build or re-sign
occurred. Artifacts and raw logs:
`target/n1g2/grant-attribution-cf80ca810/`.

- Baseline test SHA-256:
  `1b0376f982094ef4ef42e8ebb655d5866720234e993411c1ba186813014c9cfd`.
  Ten guest tests passed in this diagnostic sample.
- Integrated test SHA-256:
  `84d3d4026ee28de820eac381f63aaf145cb383bac843e810f946f610d902fd92`.
  Run 3 reproduced the exact-grant refusal; nine passed. Other captures
  include correctly handled Gate withdrawals. These are instrumented
  attribution samples, not replacement acceptance receipts.

Integrated run 3 records preparation refusal (rows 11–13), with no committed
residency at VA `0x6000008000`, and an overlapping physical alias at IPA
`0x9b00004000`, owner generation `0x31f`, logical length `0x1000`, physical
length `0x4000`. The owner-selected request is MM 2/incarnation 1/reservation
generation `0xa65`, sequence `0xfa2`, anonymous RW. It follows a correctly
handled Gate withdrawal at generation `0xa62`. The physical adapter treats
both an unaccounted alias and a still-owned provisional publication as
`Declined`. The deterministic witness isolates the latter, without running
brk maintenance or relocated table resolution.

Red logs: `/tmp/n1g2-grant-witness-red.log`,
`/tmp/n1g2-grant-base-witness-red.log`,
`/tmp/n1g2-grant-base-witness-red-2.log`.
The witness patch used on baseline is
`/tmp/n1g2-uncommitted-grant-witness.patch`.

The attempted second integrated red build (`/tmp/n1g2-grant-witness-red-2.log`)
failed to compile after cross-worktree debug target reuse; it is not a
semantic red. The workspace debug artifacts were invalidated before green
verification. Retained signed artifacts were not modified.

The correction retains a completion producer for each exact unpublished
physical incarnation, through descriptor settlement or rollback. Consumers
hold only the wait, enroll then recheck readiness, release execution capacity,
and reselect through the owner after completion. Scalar read continuations
retain their completed prefix; owner-selected file faults park without a
syscall token. The existing MM grant ledger now retains fresh publications
as well as replacements. No timeout, retry budget or timing knob changes.

VM-free verification covers actual preparation, no second allocation,
rollback wake, late enrollment, distinct completion at the same VA, and an
applied descriptor receipt. The full HVF non-serial library run passes
713 tests (3 ignored, 18 serial-host tests excluded); runtime compile-check
passes. Full CI, loom and exact signed acceptance remain pending.

## Clear-child-tid identity correction

The exact captured-thread refusal is reproduced by a real VM-free nonleader
exec in `serial_host_child_tid_clear_survives_nonleader_exec_identity_change`.
Exec promotes the survivor's Linux TID while preserving its runtime registry
ID. The previous guard compared these separate domains. The red checkpoint
is `ef2f1ab23`; `/tmp/n1g2-child-tid-red.log` contains the same refusal as the
signed anonymous/fork-COW failures.

Capture and sibling drain now use the Kernel thread's typed `registry_id()`;
exact thread and MM custody still govern retirement. The green witness
rejects a different registry runner and the old MM, then completes clear,
wake and exit publication exactly once. All six `child_tid_owner_tests`
pass serially (`/tmp/n1g2-child-tid-green.log`). Signed attribution remains
pending the final exact-artifact gate.
