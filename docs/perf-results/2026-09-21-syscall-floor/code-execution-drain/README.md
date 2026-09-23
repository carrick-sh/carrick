# Active instruction-content revocation and drain

2026-09-22. Contract: `kernel.mm.native-code-drain`. This is a VM-free
correctness prerequisite for the [resident native-region design](../native-islands/design.md).
It grants no executable publication authority and enables no native executor.
The user requested a handoff before further development or signed validation.

Participating host writes now revoke affected physical-page observations and
wait for their active users to leave before modifying bytes. Future entries
refuse revoked observations. The registry mutex is released during the wait;
unrelated pages remain active. Normal valid scope exits use atomics. The write
path retains at most one pending page reference while draining and prunes that
reference under the registry lock, so concurrent last-observer retirement does
not leave dead entries. There is no per-write pending-page vector allocation.

`PreparedInstructionContent` retains an authenticated copy and receipt, then
activates only inside the exact real kernel `NativeExecution` scope. Activation
checks task/kernel/MM/execution identity and live mapping revisions before and
after transport admission. `ActiveInstructionContent` is a non-transferable
borrow that finishes before its execution scope can end. Its checkpoint observes
revocation and actual pending native control. HAL backends without the capability
fail closed. Missing private RX, hardware-store, raw/internal-write and physical
publication authority remain explicit; these types expose no executable address.

## Red and green evidence

- `red-active-write.log`: API-only control admits a writer while content is live.
- `red-retirement.log`: deterministic retained-reference control leaves a dead
  registry entry after the final active scope disappears.
- `content-final.log`: 22 passing tests, including partial admission rollback,
  64 entry/write races, two readers, unrelated scope and registry cleanup.
- `runtime-contract-complete.log`: real carrier fixture and kernel execution
  scope pass wrong-MM refusal, actual interrupt propagation, post-write staleness,
  fresh recapture and permission-revision invalidation. Warm activations allocate
  zero heap objects at scales 1/8/32/128, with a real positive allocator control.
- `borrow-contract.log`: two compile-fail tests enforce lifetime and exclusive
  activation. Its initial zero-test section is the other rustdoc test phase;
  the two relevant tests actually run and pass in the subsequent section.
- `syscall-cost.log`: the existing write contract still measures zero warm
  allocations and exactly N affected-page visits at 1/8/32/128.
- `check-scope.log` and `registry.log`: runtime compile-check and registry pass.
  Registry at this step: 36 contracts, 15 claims, 86 surfaces, 338 syscalls,
  14 syscalls with claims.

Earlier failed test setup runs are retained. `runtime-contract.log` lacked the
allocation-metrics feature; `runtime-contract-corrected.log` captured content
before creating the second MM, which advanced the inventory revision and correctly
caused `StaleInstructionRead`. The fixture now builds both MMs before capture.
No revision validation was weakened. The final run has the required feature.

This directory records the pre-handoff source and logs. `source-inputs-sha256.txt`
identifies the captured 2,480 source inputs; `source-revision.txt` hashes that
manifest. `implementation.patch` compares the saved before-step files to this
step plus its two new files. Later handoff formatting touched three older tests,
not the drain implementation; the separate session-handoff receipt records it.
The contract, surfaces and registry snapshots here belong to this step.

## Limits and next step

No signed native publication/drain test, original inotify09 run, new performance
comparison, full CI or signed promotion was performed for this step. Zero warm
allocations do not mean zero overhead. Active ranges can require repeated tree
lookup while draining; the affected-page counter is not a proof of every lock
or lookup cost.

The read-only readv offset failure, fresh-publication invalidation-budget failure,
intermittent anonymous foreign-copyout failure and unqualified Linux private-file
alignment fixture remain open in the preceding evidence. They are not closed
by these tests. See [syscall-code-writes](../syscall-code-writes/README.md) and
[code-content](../code-content/README.md).

Continue with proven private RX admission and exact retained backing, complete
writer coverage or exclusion, code/direct-link publication and drain, current-MM
DSR lowering and exact native/HVF handoff. Keep the next delivery the unchanged
original workload with both race participants. The last accepted original
reference remains 21.885 s / 5.980 s = 3.66x; no new improvement is claimed.
