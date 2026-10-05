# N1 grant-release ordering gate: copyout green, ownership blocked

**Not review-ready.** Tested source is
`d7151718089625289b6665546e0bc10da8b5f3ab`, rebased onto batch-six main
`b2e77e2ff`. Copyout passes **10/10**, both hellos pass, and all cleanup is
zero. The six comparisons still have functional failures; these are not
equivalent to main's serving/exit-budget reds. This receipt and its diagnostic
overlay do not change the tested executable source.

## Ordering question settled red-first

The production completion could wake before releasing the publisher's temporary
stage-2 pin. At `20bd5f011`, the extended VM-free witnesses
`concurrent_transfer_waits_for_exact_uncommitted_physical_grant` and
`transfer_partial_remap_keeps_dirty_neighbor_in_same_compound` both observe
pin count **1**, required **0**, inside the exact completion callback.
`3821fddaf` commits those reds. `086d9868b` releases the temporary pin before
completion on applied settlement, rollback, and the shared import commit path;
rollback retains completion through every inventory/registry guard.
All 11 focused transfer tests pass. No wait budget, allocation policy,
concurrency, or retry behavior changed.

Clean-tree reconciliation changed two HVF abort fingerprints and capture
provenance only: 663 authority rows and 621 macOS capture rows, no classification
or debt changes. Full **`just ci` passed**, including rustdoc and integration;
**`just test-loom` passed 8/8** (two fd, three kernel connect/wake, three
terminal-clear models). The new ordering proof is the callback witness, not
those unrelated models. GitHub `work/n1` was force-with-lease pushed from
`99ff9d28257cb2c7ea9f53327fac71c2d0d690ca` to the tested SHA before publication.

## Exact fixtures and artifacts

The trusted native Linux VM `carrick@10.14.14.66` ran
`just fixtures-publish d7151718089625289b6665546e0bc10da8b5f3ab` in clean detached
`/home/carrick/dev/wt-n1g4-publish-d71517180`. Its owned temporary worktree and
temporary fixture transport ref were removed after transfer/hash verification.
No Docker was started or used as an oracle.

Bundle manifest address:
`d2dc3f5ee336dd522cbb6d30ff09365b7cf9578c696ee308754a962f3f198450`.
Archive SHA-256 on VM and Mac:
`101c58076f6557143c65deb1b5f91a4ba8fddc7939362b7cb6eac70cbc9ad6ac`.
Archive is retained under `target/fixtures/published/<tested-sha>/`.
Restore verified **1,133 executables**, with one durability flush.

| Artifact | SHA-256 | CDHash | LC_UUID |
|---|---|---|---|
| CLI | `ba4bb6d4dfce88b080bf710f47e96b5b1d23ef6b0957f35c9380bcb2db88d07a` | `854ee504ad4f3e0dc77fa58de572ada8fd3939d6` | `1A563E2C-DFBB-3C00-ADAB-35AE1AF44B4F` |
| Scheduler tests | `b96f992df8ab8f558fd3ebc55ae1fab1751a359f0e498b90c52a371e6235c82c` | `858e5b9b5d3aa294a042a81e79c81f9477dc0349` | `F42F249A-0B91-3E4F-A8D7-09E441BFB96C` |
| Copyout tests | `4516001659c1ed31065cd98449883290c965b16cfc08bef64801aa9e60525f5c` | `00de91f751e77d5dda425ecac384da5392c1599c` | `0C5C7810-9677-3C52-8394-DF3981E0AE6E` |
| Hello tests | `e8792ae413e7eb9cf591d716c8b6249a1320084dc110aff7aecc4ddec4756e3d` | `94dd3ca3a6a17534b342acec90a8ce396ca31f73` | `878E07C5-A45B-3F6B-9E4D-CBE88452D767` |

All carry hypervisor entitlement and `__dof_carrick`; the standard signer
signed 31 test executables and passed the unentitled negative control.
Guest scheduler SHA-256:
`985e13b6aee6d5e24950329bbe3fa13a095633d95f02ff0ed14619659d2e4692`.
Guest copyout SHA-256:
`d925c73ed2993e4714274566d6be38134d380f62e5b2487996cb25e678323a3b`.

## One exclusive signed gate

Invocation: `just lease gate /bin/bash /tmp/n1g4-ordering-gate.sh <tested-sha>
<bundle>`. The exclusive lease covered restore, `just build`, standard signing,
embed/CLI hello, six comparisons, ten uninstrumented copyout runs, fork traces,
and scoped cleanup. `RUST_LOG` was unset. No retries or changed budgets were
used. Artifact hashes match before and after execution, including after the
later VM-free diagnostic. CLI stdout is exactly `hello world`.

Each copyout run completed the unchanged 300-round race fixture. All six
comparison tests returned 101:

| Test suffix (`el1_`) | Result on this artifact |
|---|---|
| `anonymous_reservations_stay_in_guest` | Scale 64 completes `ok=true`, serves 67 mmap and two brk; the next root fails with the pool collision below, before scale 256 completes. |
| `delegated_root_concurrent_vma_ops` | Guest fork fails; traced owner refusal is EBUSY at stage 6. |
| `delegated_root_map_fixed_over_cow_pages` | Guest fork fails at round 0. |
| `fork_cow_resolves_in_guest` | Runtime pool collision before measured acceptance completes; the error alone does not identify the exact warm-up/measured invocation. |
| `thread_lifecycle_ptrace_traceclone` | Guest fork fails; traced owner refusal is EBUSY at stage 6. |
| `thread_lifecycle_spawn_slope` | Guest fork fails. |

The historical main comparison is the table in the
[batch-five receipt](2026-10-04-n1-batch5-gate.md), source `51bfe67f4`.
Its cloudmac raw path no longer exists; no fresh main control was run or
claimed. Four fixtures still fail before main's completing fork workloads;
anonymous advances past its first-scale assertion but introduces a later-root
functional refusal. Copyout 10/10 therefore does not confer review readiness.

Summary: `ten=0 hello=0 cli=0 six=1 traces=0`; combined gate exit **1**.
Every one of **21 unique run IDs** reports zero remaining Carrick processes.
The foreground command returned, releasing its exclusive lease.

## Next blockers: physical structural custody and pooled-root reuse

Both required captures completed with closed-child controls, errors=0,
bounded=0 and zero trace CLI exits under `--require-script-exit`. Trace success
authenticates capture, not the external guest tests, which returned 101.

```text
VMA:    errno=16 stage=6 parent_mm=2 child_mm=3 generation=12
ptrace: errno=16 stage=6 parent_mm=2 child_mm=3 generation=8
```

The prior stage-3 EINVAL/check-3 refusal is absent in these captures. Stage 6
is physical custody. `ForkPhysicalCustody::retain_extent` searches global
owners, then the legacy `carrier_stage2_records` alias index. However,
`StructuralBackingOwner::new_in` / `new_pooled_root_in` publish backing in the
record-ID authority and `structural_backings`, without populating that legacy
index. The existing `stage2_record_covering` resolves these exact records and
is already used by UserTransfer.

The post-gate VM-free diagnostic creates two real structural backing owners,
proves both exact records cover the selected source/destination, then asks the
production fork custodian for a bounded StructuralCopy. It fails **0/1** with
`exact live structural custody must not be declined by the legacy carrier-MM
alias index`. This proves a physical-custodian defect consistent with stage 6;
the trace does not name the refused selection's actual IPA. The red source is
preserved in [the diagnostic overlay](2026-10-05-n1-structural-custody-red.patch),
applicable to the tested SHA. It was removed from active source after capture,
not ignored or represented as passing CI. No production repair is included.

Independently, anonymous and fork-COW report:

```text
stage-1 extension arena IPA 0x9a00000000 is still held by the root-slot pool
```

The unique producer is `MmAccessState::publish_raw_stage1_arenas_into`: this
MM has no structural-owner row for that 2 MiB base, `allocate_slot_at` refuses,
and the carrier pool contains the IPA. The exact holder and logical arena
source reuse have not been captured; do not equate this with the stage-6
selection refusal or bypass it with private backing. Next work needs exact
structural record lookup/custody and a two-root carrier witness for primary
relocation, retirement and subsequent pool admission.

All raw evidence, retained executables, image/fixture identity, gate script,
red/green ordering logs, CI/Loom/publish logs and cleanup receipts are retained
in `target/n1g4/ordering-d71517180/`. Whole-N1 acceptance and N2/N3 workload
budgets remain open. No review-ready post or draft PR is warranted.
