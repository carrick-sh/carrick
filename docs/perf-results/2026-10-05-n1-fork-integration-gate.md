# N1 fork gate on the integrated shared owner

## Exact signed cycle

Tested source: `ea0b4c26b27d032137d7eed1fe999dd0041303d4`, on integrated
N1 `229194ae6488e846ce2ceabad59b4703e619a8fb` with x86 orders 1–3 and the
fixture lock refresh. Evidence:
`/Volumes/carrick-build/evidence/n1-cm/fork-ea0b4c26b/`.
`results.tsv` records five signed tests and three traces against `50d648e76`;
`runner-results.tsv` preserves the original runner statuses.

The director-supplied fixture archive SHA-256 matches
`92f82afb224bdc5b0e84197fdc68e60eb4746e6b19e75971f7a86ac66aca921b`.
Restore and each signed input verification identify all 1,133 executables.
The exclusive host lease covered restore, the forced EL1 image rebuild,
build/signing, tests, traces and scoped cleanup. No Docker, load generator,
retry, altered budget or full signed acceptance was used.

Touching `crates/carrick-el1-image/build.rs` under that lease forced fresh
nested images. Full image bytes match all six retained Mach-O artifacts:

- Signed test image, 457,704 bytes:
  `e56703620e8912f2e5722f38bdf000debbf4fae38d6edd739cfe8f6c03a48e20`.
- CLI image, 453,912 bytes:
  `ff4ebb11fdbec666f20e7c9b0bacce2c9afbc9b274e2e3436bc950a354bf90b7`.

Raw images, symbol ELFs, fixture/image receipts, layer hashes, binaries,
SHA-256, CDHash, LC_UUID, entitlements, DOF load commands and source snapshots
are retained. All eight scoped cleanups returned zero. The artifact hashes
and live fixture/CLI hashes remained stable. The cycle returned **1**.

## Every first failure changed

**None of the five tests passes.** Each stops at the same new earlier failure:
`HVPatch COW compound IPA 0x2e00000000 has no exact inventory coverage`.
VMA, fixed-over-COW and ptrace again fail during child vvar COW. Their later
`50d648e76` results cannot establish progress on this integrated artifact.

| Test suffix (`el1_`) | First failure at `50d648e76` | Integrated result |
| --- | --- | --- |
| `delegated_root_concurrent_vma_ops` | Parent completes eight rounds; child exits 139 | New vvar inventory error; libtest 101 |
| `delegated_root_map_fixed_over_cow_pages` | Round 0 `parent-wait-f`; child exits 139 | New vvar inventory error; libtest 101 |
| `thread_lifecycle_ptrace_traceclone` | Initial stop succeeds; options errno 38 | New vvar inventory error; libtest 101 |
| `thread_lifecycle_spawn_slope` | Terminal settlement: task 2 changed after exit preparation; carrier SIGABRT 6 | New vvar inventory error; libtest 101 |
| `fork_cow_resolves_in_guest` | Warmup succeeds; measured 16-page workload exits 139 after 16 EL1 COW resolutions | New vvar inventory error in warmup; libtest 101 |

Each of the three refusal traces qualifies its publication and completion
controls and prints:

```text
OWNERFORKREFUSAL1|summary|closed_children=2|refusals=0|guest_results=1|witness_closed=1|errors=0|bounded=0
```

There are no refusal/check-ID/arena companion rows: the failure is later than
owner Fork admission. Instrument exit zero is distinct from the workload's
libtest 101 / raw wait status 25856. All three traced workloads fail.

## Co-evolution diagnosis and red witnesses

The native producer in integrated N1 is byte-identical to the producer before
`52d2540bc`. The `be40000e3` physical-extent correction and its witness were
dropped during integration. Order 3 moved pin, reference and retirement
authorities into `carrick-core`; the native leaf-to-inventory producer still
publishes the selected 4 KiB leaf as its physical inventory extent.

LLDB on the retained signed fixed-over-COW executable stops at the child
vvar refresh. Its complete event ring contains 31 entries with zero errors.
The typed inventory walk covers all 518 rows / 85 nodes and finds:

```text
OWNERINVENTORY1 vvar key=(0x2e00000000,0x1000) frame=12 mapping=287 stage2=(0x2e00000000,0x4000) generation=5
```

`vvar-coverage.core`, the LLDB transcript and scoped cleanup are retained.
The first optimized error-closure breakpoint did not fire; its failed capture
is preserved separately, and supplies no core/ring evidence. The successful
capture stops at the known refresh entry before the refused physical COW.

The policy extraction moves granularity and deduplication into
`carrick-core::mm::frames::ForkFrameInventory`, retaining the backend's exact
physical pin and parent inventory adapter. It creates no second inventory
or retirement authority. Before correction, both neutral core witnesses fail
on 4 KiB versus native/canonical extent selection. The restored original
producer/consumer witness calls this core path and fails with the exact
signed compound-coverage error. Authoritative red receipt:
`core-inventory-red2.log`. The first attempt's native compile error is retained
in `core-inventory-red.log` and is not a behavioral red witness.

The core contract retains one source extent per physical inventory identity,
independent of selected leaf/alias population, without changing the parent.
It distinguishes a logical COW fragment from a larger native stage-2 lease.
Signed verification of the correction requires a new exact fixture bundle.
File-table lease, clone-TID, copyout and brk behavior are outside this change.

The correction chooses the canonical source inventory extent, or the full
pinned structural allocation when there is no source row. The core publishes
it once and the native adapter carries the original frame/mapping, backing,
stage-2 lease and exact owner. `core-inventory-green.log` passes 94 focused
tests (including the two neutral witnesses and all five native owner-fork
tests), workspace all-target clippy, fmt-check and diff-check. This is VM-free
proof, not a signed improvement claim.
