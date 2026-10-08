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

## Initial rebased-stack audit, before restoration

The director requested a witness audit of every pre-rebase fork fix, plus
the anonymous owner-fault correction. `stack-audit.tsv` in the evidence
directory records all ten: **five kept, one ported, four dropped**. Here
"kept" means that the production guarantee and its witness survived the
core extraction. "Dropped" describes an integration regression, not a
deliberate retirement or a completed repair.

| Original fix | Classification | Witness result on the integrated core path |
| --- | --- | --- |
| `c4b1836c4`, private identity copy | Kept | The two-live-MM fork witness fails with 66 custody entries instead of 6 when structural copy expands beyond identity pages. |
| `dc85ec647`, live-leaf COW settlement | Kept | The no-host-arm witness fails with `span is not COW-armed` when the old host coverage requirement is reinstated. |
| `f5121942c`, later owner edits | Kept | Both retirement and later fork-arm witnesses fail when settlement again requires the stale completed-write descriptor shape. |
| `474d70f0e`, live-leaf vvar refresh | Kept | Both no-host-arm and clipped-neighbor witnesses fail when COW span selection uses only host arm metadata. Their native readonly import coverage was separately dropped. |
| `e6411c853`, vvar permission ceilings | Dropped | Initial/exec image and native/tagged COW ceiling witnesses are absent. Image builders add vvar after stage-1 sealing; native execute ceilings are absent. The signed vvar leaf is again `0x07a0002e00000fc3`, recording W/X intent. |
| `1ce444334`, readonly leaf adoption | Dropped | Its witness is absent. The shared core's AArch64 fork-arm hook still adopts only AP_RW leaves, excluding native AP_RO vvar. |
| `be40000e3`, physical inventory extents | Ported | Two neutral core witnesses and the restored native producer/consumer witness fail before `452fd0e67` and pass after it. |
| `2414ef7dd`, bound table custody | Dropped | The native-vvar fixture no longer removes its fixed-VA table row. Production COW still requires that row instead of resolving the actual manager's physical arena. |
| `efc86a9fd`, identity stamp authority | Dropped | Both owner-selection and structural-pin witnesses are absent. The closed identity-write capability was removed; kernel stamping reverted to ordinary `write_bytes`. |
| `b26645d94`, anonymous owner fault | Kept | Both ISA clipping witnesses fail without live-neighbor clipping. The actual fork fixture and both ISA fixtures fail when the admitted owner venue is replaced by the old unselected lazy request. |

The audit temporarily reverses semantics in the current extracted code,
rather than restoring old modules that conflict with order 3. Every edited
file is restored byte-for-byte in a `finally` block. All eleven positive
tests pass again after restoration. Core extent red/green receipts are
separate; none of these VM-free controls requires an HVF VM.

Initial audit receipts are under `stack-audit/`: the preserved `attempt1/`
receipts, `owner-venue-controls.tsv`, and source comparisons.
`dropped-witnesses.json` verifies all eight original witness names or
fixture shapes present at `50d648e76` and absent at `452fd0e67`.
`integration-dropped-code.patch` and the original fix patches preserve
the source comparisons. The first settlement control failed to compile
because a helper had been removed; its attempt is retained and excluded
from behavioral evidence. Disabling anonymous clipping alone leaves the
one-page fork fixture green: that fixture proves the owner handoff, while
the two ISA fixtures prove neighborhood clipping. Both guarantees have
qualified negative controls; the incomplete reversal is also retained.

The four dropped guarantees were **not repaired by the extent port**. They
needed correction in the shared owner path with restored red-first witnesses;
old AArch64 frame retirement authorities must remain retired. Their original
signed failures are obscured on this artifact by the earlier inventory
error. No signed pass or complete integration closure is claimed, and no
file-table, clone-TID, copyout or anonymous-brk code was changed.

## Restored ports and order 4 audit

The director requested restoration of all four dropped guarantees, one
commit each. These ports now accompany the physical extent correction:

| Original fix | Port after rebase | Restored guarantee |
| --- | --- | --- |
| `be40000e3` | `29ccd7263` | Core-owned canonical physical extent selection and deduplication |
| `e6411c853` | `65bab0a1d` | Initial/exec vvar sealing and native RO/NX permission ceilings |
| `1ce444334` | `9aeaf6611` | Readonly native leaf adoption by the existing fork-arm hook |
| `2414ef7dd` | `561712029` | Actual page-table arena resolution through retained custody |
| `efc86a9fd` | `6607b0281` | Closed identity-word publication through the shared MM owner |

The identity capability and validation live in `carrick-core-abi` and
`carrick-core`. AArch64 supplies the control-page location and hardware
translation facts, then transports the admitted word through the existing
owned transfer. An x86 projection tests the same core policy. The split
memory view forwards that capability without granting ordinary user writes.
Native descriptor encoding, physical pins and table transport stay in their
existing backend; no retired native frame authority was restored.

Each port restores its original witness and records a behavioral red before
correction. The four ports were developed on the physical-extent tip
`452fd0e67`; table-custody tests also require readonly adoption to reach the
table lookup. Port receipts are `ports/e641-red.log`, `ports/1ce-red.log`,
`ports/2414-red.log`, and `ports/efc-red2.log`, with green receipts beside
them. Early compile errors and fixture-adaptation failures are retained and
excluded from red or green claims. The identity port additionally has an
x86 semantic reversal and a split-view forwarding reversal.

The completed stack rebases onto x86 order 4 at
`56bf8c0caefe39fcc2260345d0a54772a74bffad`. The only conflict was the
generated macOS authority capture, where the new base was retained pending
recapture. The fixture-lock commit was already upstream and was omitted.
`ports/order4-rebase.log` records this transition; the previous stack remains
on `n1-cm-before-order4-ee105fb96`.

The repeated whole-stack audit on source
`6607b02817c24a93156e49f3abc149aa591f47d6` classifies **five kept, five
ported, zero dropped**. Nineteen negative commands produce behavioral test
failures covering every guarantee. After exact restoration, all 25 positive
tests pass. All temporarily edited files are restored byte-for-byte and the
tracked tree is clean. Authoritative final receipts are
`stack-audit-order4.tsv`, `stack-audit-order4/controls.tsv`,
`stack-audit-order4/summary.json`, and `stack-audit-order4-gate.log`.
The final audit initially reused negative-control filenames; those final
receipts were moved into `stack-audit-order4/`. Initial `attempt1/` and
separate owner-venue receipts remain. Signed evidence was not overwritten.

## Pause boundary

The director paused N1 in favor of settling x86 on the shared core. All
ports are committed; no fix is in progress and no further signed cycle will
run during the pause. The exact `ea0b4c26b` signed result remains red for all
five tests. The new ports have VM-free verification, not a signed pass.
The handoff in `2026-10-05-n1-cm-pause-handoff.md` lists every fix, open
failures and the next verification step after the settled-core rebase.
