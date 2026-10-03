# Required TLB invalidation fixture isolation

Contract: `kernel.mm.tlb-maintenance-budget`. Base: `a257cdf9d`,
`work/tlb-budget`. No Docker was run. The minimum slope of 96 owed
invalidations and the zero added host-maintenance budget are unchanged.

## Mechanism

The original fixture spawned a sibling but did not wait for its runtime
initialization. Rust's sibling alternate signal stack used a 16 KiB anonymous
mapping with a 4 KiB `PROT_NONE` guard. While the main thread's last allocated
file page was between `munmap` and `MAP_FIXED`, the sibling could allocate that
temporarily free address. The main thread then replaced part of the sibling's
mapping. Its guard protection and teardown became additional host-lane edits
of the measured file page. The subtraction between 4 and 36 rounds therefore
included different work, despite identical printed loop counts.

[The qualified USDT capture](attributed-97.dtrace) records a disjoint short run
(file `0x6000209000`, sibling teardown `0x600020b000+16384`), then an overlapping
long run (file `0x600020a000`, sibling teardown `0x600020a000+16384`).
[Its test output](attributed-97.log) attributes the long run's extra debt to
`munmap`: 72 `mprotect`, 38 `munmap`, one `mmap`, producing a slope of 97.

[The undercount capture](attributed-94.log) has the converse interleaving:
the short run owes 16 (9 protection, 6 retirement, one mapping), versus the
long run's 110 (72 protection, 37 retirement, one mapping). The short file
address appears five times in the retirement origins for four rounds. Every
owed debt completes on return, but the subtraction is 94 and fails the
unchanged minimum. This is extra scaffolding work in the short run, rather
than evidence that a required file edit skipped invalidation.

The production paths are unchanged: `apply_stage1_rules` and
`retire_stage1_range` batch required descriptor invalidations;
`invalidate_after_edit` owes the final ASID invalidation to the syscall
return; the mailbox resume entry issues it and `complete_on_return` accounts
for completion. Host fallback runs `run_stage1_maintenance`. No migration,
retry, or resume-invalidation algorithm was changed.

## Red-first binding and correction

`el1_tlb_mm_edit_window_excludes_sibling_allocations` deliberately asks the
sibling to allocate and touch 16 KiB after the first file-page retirement and
before its fixed remap. Both acknowledgements use bounded futex waits; a
timeout fails the fixture instead of starting the loop.

[Without the surrounding reservation](forced-gap-red.log), this deterministic
interleaving reports `sibling_gap_overlaps=true` and fails the fixed remap with
`ENOMEM`. [With the reservation](forced-gap-green.log), the same signed host
executable reports `sibling_gap_overlaps=false` and completes all 36 rounds.
The replay deliberately controls the otherwise scheduling-dependent mmap
interleaving; it is a signed binding because guest runtime startup and the
guest allocator cannot be proved by a host-only page-table test.

The corrected fixture reserves 64 KiB of `PROT_NONE` space before spawning
the sibling, waits for the sibling's initialization acknowledgement, and
places the file page in the window's interior. The 4 KiB transient hole is
bounded on both sides and cannot fit the sibling's 16 KiB stack allocation.
The regular sibling performs no further allocation while parked. This does
not claim thread-private ownership of arbitrary unmapped addresses in a
shared Linux MM; arbitrary one-page sibling allocations would need a separate
contract. The forced allocation tests the actual startup mapping shape.

## Diagnostic provenance

The unmodified host test executable used for [the 98 observation](original-98.log)
has SHA-256 `287b6c9edfdacc42e7f2fb8276fa385767d5e1c94cac87d03c20efe01640fd2f`.
Temporary diagnostic counters, then a bounded origin ledger, attributed debts
without pid fasttrap perturbation. Those temporary Rust changes were removed
from the final diff. Diagnostic host executable hashes were:

- 97 capture: `d95b6e1560e610095c6cd2040714051079845654ef8d756442766cff742a610a`.
- 94 capture: `94d3a3f43fb5494b2d2c8b24677f45f9e6c5c002a5ba1106f427ee22047cc645`.
- Forced red/green: `02c322fa4465062be3dbe6279a46a2846d77818e742c353f16a687c3ba3fe148`,
  CDHash `a1d746e8025deb1ae8fd02232008b0bbc0cbf0b2`.

The forced red/green runs kept that host executable and rebuilt only the guest
fixture. The final signed repetitions rebuild both through the normal wrapper.

The durable accounting script is
[`hvpatch-resume-tlbi-accounting.d`](../../../scripts/dtrace/hvpatch-resume-tlbi-accounting.d).
Use `dtrace -C -Z -s SCRIPT -p PID`; `-DUSDT_ONLY` omits pid fasttrap sites.
The embed carrier runs in the test process. USDT service-begin argument 3 is
the Linux syscall number; the args companion carries number and arguments
0..3. Full mode additionally attributes the debt function entry. Captures
measure counts, not timing; no DTrace drops were reported. Every completed
diagnostic run was cleaned with its exact run ID and reported zero remaining
Carrick processes. One separate traced workload failed `ENOMEM` at round 19;
it was excluded from completed-workload counting evidence.

Final repetition logs and individual signed-artifact receipts are retained
under `target/tlb-budget-evidence/`. The clean-commit host+signed acceptance
receipt is produced by `just accept` under `target/el1-gate/<commit>/receipt.json`.
That receipt, rather than an earlier focused run, determines acceptance.

## Final focused verification

Ten consecutive normal signed-wrapper runs (`tlb-budget-final-01` through
`tlb-budget-final-10`) each completed with 15 short-run debts, 111 long-run
debts, slope 96, and zero added host-maintenance invalidations. Every wrapper
and scoped cleanup exited zero; individual artifact receipts accompany the
logs. Full-mode tracing on the corrected fixture reported 233 syscall
services and 126 debt entries (15 + 111), without drops.
