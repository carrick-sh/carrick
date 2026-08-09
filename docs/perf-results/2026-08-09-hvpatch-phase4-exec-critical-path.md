# HvPatch Phase 4 exec critical-path closure

Date: 2026-08-09

Status: **ATTRIBUTED; Phase 4 remains RED.** The post-load exec path now has a
closed outer runtime ledger and a reconciled inner engine ledger. This is
traced attribution, not an untraced performance result.

## Question

The initial replacement-stage instrument accounted for materially less time
than the `execve-loaded` to `execve-sysregs` window. Was the remainder hidden
inside Hypervisor.framework, image replacement, or Carrick runtime work before
the engine call?

## Provenance

- Host: macOS 27.0 build `26A5388g`, arm64.
- Branch: `codex/hvpatch`, parent `0a17cb4b`, with only the typed ledger changes
  described here uncommitted at capture time.
- Signed binary SHA-256:
  `05ebba4fde8d0178831fb82716513f7bdbb41d34c7b98b20ccc5ea39006e86b3`.
- Backend: `--exec-backend hvpatch`; filesystem: `--fs host`.
- Workload: `scripts/perf/fixtures/hvpatch-cold-go-build.sh` in
  `localhost:5005/carrick-go-conformance:1.24`, `--pull never`.
- Every cited run printed exact `ok` and `BUILD_OK` markers. Carrick and Docker
  were not run concurrently.

## Instruments

The append-only `hvpatch-exec-replace-stage` ABI now includes the two regions
the first ledger omitted:

- phase 7: process-bank plan rebase/cache;
- phase 8: predecessor address-space teardown.

The new `hvpatch-exec-runtime-stage` ABI is a separate outer hierarchy:

- phase 0: executable identity and synthetic `/proc` state;
- phase 1: close-on-exec fd retirement;
- phase 2: thread-group sibling drain;
- phase 3: shared-VM topology-lock acquisition;
- phase 4: engine replacement (encloses the inner ledger);
- phase 5: post-engine identity/TID publication.

All fields are scalar CTF values. The D scripts join them to the typed
`hvpatch-guest-lifecycle` PID/TID/ASID record and fail closed on missing,
unknown, or unjoined events.

## Bank-plan and raw stage-2 screens

`hvpatch-phase4-exec-bank-layout.d` reported 67/67 events with no errors:

| Bank-plan result | Count | Total | Per exec of that class |
|---|---:|---:|---:|
| Cache miss | 13 | 17.646 ms | 1.357 ms |
| Cache hit | 54 | 20.882 ms | 0.387 ms |
| Combined | 67 | 38.528 ms | 0.575 ms/all execs |

The hit path is therefore not free: cloning/rebinding the cached banked plan is
already over one third of the `<1 ms` entire-exec target.

`hvpatch-phase4-exec-stage2.d` paired 2,530/2,530 raw HVF calls with zero HVF,
pairing, bounded, or DTrace errors:

| Raw HVF operation | Calls | Total |
|---|---:|---:|
| Unmap | 1,269 | 8.670 ms |
| Map | 1,261 | 9.134 ms |

Raw Hypervisor.framework calls are only 17.804 ms of the path; they do not
explain the original accounting gap.

Raw streams:

- `target/perf/hvpatch-phase4/exec-bank-layout-committed-tip.raw`
- `target/perf/hvpatch-phase4/exec-stage2-committed-tip.raw`

## Closed inner engine ledger

Command shape:

```sh
target/release/carrick trace \
  --script scripts/dtrace/hvpatch-phase4-exec-replace-stages.d \
  --trace-out target/perf/hvpatch-phase4/exec-replace-stages-complete-ledger.raw \
  -- run --name hvpatch-complete-ledger-20260809 --rm --raw \
  --fs host --exec-backend hvpatch --pull never \
  -v "$PWD/scripts/perf/fixtures:/fixture:ro" \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh /fixture/hvpatch-cold-go-build.sh
```

The consumer joined 603/603 records (nine stages x 67 execs), with zero join,
phase, bounded, empty, or DTrace errors:

| Inner phase | Total | Per exec | Share of inner total |
|---|---:|---:|---:|
| Map new host backings | 49.300 ms | 0.736 ms | 44.8% |
| Bank plan | 38.572 ms | 0.576 ms | 35.1% |
| Immutable-file artifacts | 7.189 ms | 0.107 ms | 6.5% |
| Drop old host backings | 7.364 ms | 0.110 ms | 6.7% |
| Address-space teardown | 7.114 ms | 0.106 ms | 6.5% |
| Page-table/reset metadata | 0.299 ms | 0.004 ms | 0.3% |
| Registers, mailbox, aliases | 0.178 ms | 0.003 ms | 0.2% |
| **Total** | **110.017 ms** | **1.642 ms** | **100%** |

The raw HVF map calls are only 9.134 ms of the 49.300 ms map-backing stage;
host mapping/view creation and surrounding ownership work dominate that stage.

## Closed outer runtime ledger

`scripts/dtrace/hvpatch-phase4-exec-runtime-stages.d` joined 402/402 records
(six stages x 67 execs), with zero join, phase, coverage, bounded, empty, or
DTrace errors:

| Outer phase | Total | Per exec | Share of outer total |
|---|---:|---:|---:|
| Engine replacement | 109.752 ms | 1.638 ms | 60.1% |
| Topology-lock acquisition | 72.052 ms | 1.075 ms | 39.4% |
| Close-on-exec | 0.702 ms | 0.010 ms | 0.4% |
| Proc state | 0.155 ms | 0.002 ms | 0.1% |
| Publication | 0.082 ms | 0.001 ms | <0.1% |
| Sibling drain | 0.004 ms | <0.001 ms | <0.1% |
| **Total** | **182.747 ms** | **2.728 ms** | **100%** |

The outer engine measurement (109.752 ms) and sum of its nine inner stages
(110.017 ms) differ by 0.265 ms, or 0.24%. That is the required independent
closure: the former unexplained time was not silently inside the engine.

Raw stream:

- `target/perf/hvpatch-phase4/exec-runtime-stages-complete-ledger.raw`

## Decision

The `<1 ms` exec target cannot be reached by another page-table-manager tweak:
the page-table/reset stage is already about 0.004 ms/exec. The two measured
blocking classes are:

1. shared-VM topology contention, already 1.075 ms/exec before engine work;
2. engine backing map + bank-plan preparation, 1.312 ms/exec together.

The next topology experiment must identify the holder class (in-process fork,
thread materialization/rebind, or exit cleanup) before changing lock scope.
Fork snapshots previously measured around 1.2 ms each inside the topology
critical section, making concurrent fork the leading hypothesis, not yet a
confirmed cause. Any finer-grained locking proposal must first prove that
disjoint process-bank stage-2 mutations are safe under Hypervisor.framework;
correct one-VM isolation outranks the latency target.
