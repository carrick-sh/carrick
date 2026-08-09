# HvPatch Phase 4 process-spec attribution

Date: 2026-08-09

Status: **ATTRIBUTED; Phase 4 remains RED.** Two complete typed captures show
that private address-space snapshot/remap is 63.6% of hvpatch in-process-fork
process-spec construction. Publishing the complete 1.75-MiB stage-1 table image
is the second bucket at 19.8%. Repeated page-table manager clones are real but
are not the first lever.

## Question

The parent-thread fork ledger measured process-spec construction at about
1.284 ms/fork, or 34.8% of the one-VM in-process-fork critical section. Is that
time dominated by duplicate page-table/protection snapshots across the AArch64
engine and HVF backend, or by creating the child's private stage-2 mappings?

## Instrument

`hvpatch-fork-process-spec-stage` carries five scalar CTF arguments:

- append-only stage ordinal;
- Linux child PID and forking TID;
- elapsed nanoseconds;
- stage-specific bytes or mapping count.

Stages 0 through 10 are mutually exclusive: parent table load, vCPU snapshot,
parent table clone, table rebase, alias union, private snapshot/remap,
validation, table publication, backend protection snapshot, backend spec
finalization, and wrapper protection snapshot. Stage 11 is the cumulative total
and must not be summed with its enclosed stages.

The durable consumer is
`scripts/dtrace/hvpatch-phase4-fork-process-spec-stages.d`. It distinguishes
Linux guest PID/TID from Darwin DTrace `pid`, stays within the five-argument
macOS USDT ABI qualified on this host, and exits nonzero on zero events, any
missing stage, bounded capture, or DTrace error. Perturbation is twelve
low-frequency USDT events and timestamp reads per successful guest fork. Only
same-instrument ratios are citable.

## Provenance

- Host: macOS 27.0 build `26A5388g`, arm64.
- Branch: `codex/hvpatch`, committed parent `5f1795db`, with only this typed
  instrumentation, D script, and evidence document uncommitted at capture time.
- Signed binary SHA-256:
  `2ddc121090e50083be1dd3f1c56636f2973938f9085883960701f26d0fc0adc2`.
- Backend: `--exec-backend hvpatch`; filesystem: `--fs host`.
- Workload: `scripts/perf/fixtures/hvpatch-cold-go-build.sh` in
  `localhost:5005/carrick-go-conformance:1.24`, `--pull never`.
- Both runs printed exact `ok` and `BUILD_OK` markers. Carrick and Docker were
  not run concurrently.

Command shape:

```sh
CARRICK_RUN_ID=<scoped-id> target/release/carrick trace \
  --script scripts/dtrace/hvpatch-phase4-fork-process-spec-stages.d \
  --trace-out target/perf/hvpatch-phase4/<capture>.raw \
  -- run --name <scoped-id> --rm --raw --fs host \
  --exec-backend hvpatch --pull never \
  -v "$PWD/scripts/perf/fixtures:/fixture:ro" \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh /fixture/hvpatch-cold-go-build.sh
```

## Capture validity

| Capture | Count for each phase 0..11 | Empty/bounded/DTrace/stage errors | Result |
|---|---:|---:|---|
| `fork-process-spec-stages-1.raw` | 68 | 0 | `ok`, `BUILD_OK` |
| `fork-process-spec-stages-2.raw` | 68 | 0 | `ok`, `BUILD_OK` |

The captures contain 136 complete process-spec ledgers. Raw captures are
retained under `target/perf/hvpatch-phase4/`.

## Closed process-spec ledger

| Stage | Combined total | Mean per fork | Share of cumulative total |
|---|---:|---:|---:|
| Private snapshot/remap | 117.327 ms | 0.863 ms | 63.62% |
| Publish page-table image | 36.461 ms | 0.268 ms | 19.77% |
| Backend spec finalization | 8.240 ms | 0.061 ms | 4.47% |
| Parent page-table clone | 7.844 ms | 0.058 ms | 4.25% |
| Page-table rebase | 2.782 ms | 0.020 ms | 1.51% |
| Alias union | 0.612 ms | 0.004 ms | 0.33% |
| vCPU snapshot and child seed | 0.227 ms | 0.002 ms | 0.12% |
| Backend protection snapshot | 0.060 ms | <0.001 ms | 0.03% |
| Validation | 0.033 ms | <0.001 ms | 0.02% |
| Wrapper protection snapshot | 0.027 ms | <0.001 ms | 0.01% |
| Lazy parent-table load | 0.021 ms | <0.001 ms | 0.01% |
| **Cumulative total** | **184.413 ms** | **1.356 ms** | **100%** |

The peer stages sum to 173.632 ms. The remaining 10.781 ms (5.85%) is
inter-stage bookkeeping and probe overhead. The result repeats independently:

| Capture | Private snapshot/remap | Table publication | Cumulative total |
|---|---:|---:|---:|
| capture 1 | 56.910 ms | 18.064 ms | 90.352 ms |
| capture 2 | 60.417 ms | 18.397 ms | 94.061 ms |

The stage-5 `units` value is the packed child-bank address span, not resident or
copied bytes. It averages about 34.2 GiB/fork because the child's large sparse
mmap arena participates in the bank layout. `mach_vm_remap(copy=TRUE)` is used
for each private mapping, so the timing does not imply that 34.2 GiB was eagerly
copied. The alias/validation ledger averaged 20.9 mappings/fork.

## Interpretation and decision

The initial duplicate-state hypothesis is only partly supported. Table
publication plus the two explicit full-manager clones account for 28.5% of the
cumulative total, so sharing or consuming one authoritative child manager may
be worthwhile. Protection snapshots are negligible. But the first behavior
lever is the 63.6% private snapshot/remap bucket.

Do not yet merge or share child mappings. The next instrument must partition
that bucket per private mapping while retaining Linux child PID/forking TID,
guest VA, extent, and elapsed time; a low-frequency companion outcome event
must distinguish `mach_vm_remap(copy=TRUE)` from the sparse-copy fallback.
That evidence decides among:

1. avoiding snapshots for immutable/reconstructable mappings;
2. coalescing compatible private backing objects to reduce Mach remap count;
3. shrinking the arena/high-water mapping extent supplied to the child; or
4. only then removing redundant page-table clones if no mapping lever is large
   enough.

Correct ASID/stage-2 isolation, the one-HVF-VM invariant, exact 68-fork output,
and the existing Phase 4 bounded-failure behavior remain authoritative. This
capture alone does not justify sharing writable private memory or weakening the
topology lock.

## Verification before commit

- Red-first typed ABI test failed until the provider declaration and real/stub
  wrappers existed, then passed.
- `cargo test -p carrick-observability`: 55 unit tests and 2 doc tests passed.
- `cargo check -p carrick-aarch64 -p carrick-vmm-hvf`: passed.
- `cargo fmt --all -- --check`: passed after formatting.
- Signed `just build`: passed before both captures.
- Full `just ci`: passed after both retained captures.
