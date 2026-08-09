# HvPatch Phase 4 private-snapshot mapping attribution

Date: 2026-08-09

Status: **ATTRIBUTED; no behavior candidate retained; Phase 4 remains RED.**
Two complete typed captures show that `mach_vm_remap(copy=TRUE)` accounts for
79.6% of the in-process-fork private-snapshot stage. The 32-GiB sparse mmap
arena is the largest mapping role, but even perfect removal of its remap cost
has only a 59.1-ms combined ceiling across 136 forks, or 29.6 ms and 0.7% per
4.27-CPU-second cold build. That is too small to close the 0.77-second Phase 4
CPU gap and below the campaign's 10% end-to-end opportunity threshold.

## Question

The preceding process-spec ledger placed 63.6% of process-spec construction in
private snapshot/remap. Is that stage dominated by one mapping role or by the
sparse-copy fallback, and is the resulting opportunity large enough to justify
a behavior change?

## Instrument

The typed CTF surface deliberately uses two five-scalar probes, joined by
Linux child PID and guest virtual start:

- `hvpatch-fork-private-snapshot`: Linux child PID, Linux forking TID, guest
  start, mapped bytes, and elapsed nanoseconds;
- `hvpatch-fork-private-snapshot-outcome`: the same guest identity and start,
  append-only mapping role, and snapshot method.

The split preserves Linux guest PID/TID and mapping shape while staying below
the macOS USDT sixth-argument failure qualified on this host. DTrace `pid` and
`tid` remain distinct Darwin host identities. Mapping-role ordinals reuse the
existing fork-footprint ABI rather than creating an investigation-local
taxonomy. Method 0 is Mach COW remap; method 1 is the resident-page sparse-copy
fallback.

The durable consumer is
`scripts/dtrace/hvpatch-phase4-fork-private-snapshots.d`. It joins both halves,
also captures process-spec private-stage and cumulative totals, and exits
nonzero on zero events/forks, an invalid private role or method, duplicate or
unpaired keys, identity mismatch, bounded capture, or DTrace error.

Perturbation is two scalar USDT firings per private mapping plus the existing
process-spec stage events. No syscall, VM-exit, page, or instruction hot path
is instrumented. Only same-instrument ratios and the order-of-magnitude
end-to-end ceiling are used below; the traced run is not a performance gate.

## Provenance

- Host: macOS 27.0 build `26A5388g`, arm64.
- Branch: `codex/hvpatch`, committed parent `6d03dbf3`, with only this typed
  instrumentation, D script, and evidence document uncommitted at capture
  time.
- Signed binary SHA-256:
  `615fc34a8e316adf983a6fea984a4a8e95615fba3b18dfb648f09b720ce009e1`.
- Backend: `--exec-backend hvpatch`; filesystem: `--fs host`.
- Workload: `scripts/perf/fixtures/hvpatch-cold-go-build.sh` in
  `localhost:5005/carrick-go-conformance:1.24`, `--pull never`.
- Both runs printed exact `ok` and `BUILD_OK` markers. Carrick and Docker were
  not run concurrently.
- Raw capture SHA-256:
  - `fork-private-snapshots-1.raw`:
    `092e52afc41c2eca6ef034dd903b3f2b95e7f5f16fa9024908db4d4619678fac`;
  - `fork-private-snapshots-2.raw`:
    `85ef0ecad7db1c8b70ec6811d322b5a22c704efa3730f2cfc37ac4428737454c`.

Command shape:

```sh
CARRICK_RUN_ID=<scoped-id> target/release/carrick trace \
  --script scripts/dtrace/hvpatch-phase4-fork-private-snapshots.d \
  --trace-out target/perf/hvpatch-phase4/<capture>.raw \
  -- run --name <scoped-id> --rm --raw --fs host \
  --exec-backend hvpatch --pull never \
  -v "$PWD/scripts/perf/fixtures:/fixture:ro" \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh /fixture/hvpatch-cold-go-build.sh
```

## Capture validity

| Capture | Joined mapping pairs | Forks/private stages | Malformed/outstanding/bounded/errors | Result |
|---|---:|---:|---:|---|
| `fork-private-snapshots-1.raw` | 1,287 | 68/68 | 0/0/0/0 | `ok`, `BUILD_OK` |
| `fork-private-snapshots-2.raw` | 1,287 | 68/68 | 0/0/0/0 | `ok`, `BUILD_OK` |

Every one of the 2,574 mapping outcomes used method 0, Mach COW remap. The
sparse-copy fallback population was exactly zero.

## Closed per-mapping ledger

| Private mapping role | Combined events | Combined mapped bytes | Combined remap time | Share of measured remap time | Mean per event |
|---|---:|---:|---:|---:|---:|
| mmap arena | 136 | 4,672,924,418,048 | 59.142 ms | 54.92% | 0.435 ms |
| writable other | 686 | 2,801,467,392 | 25.571 ms | 23.75% | 0.037 ms |
| high alias | 256 | 1,073,741,824 | 18.071 ms | 16.78% | 0.071 ms |
| page tables | 136 | 249,561,088 | 2.742 ms | 2.55% | 0.020 ms |
| read-only/internal | 1,088 | 17,825,792 | 1.230 ms | 1.14% | 0.001 ms |
| overlay | 136 | 292,057,776,128 | 0.758 ms | 0.70% | 0.006 ms |
| heap | 136 | 18,253,611,008 | 0.169 ms | 0.16% | 0.001 ms |
| **Total** | **2,574** | **4,987,378,401,280** | **107.684 ms** | **100%** | **0.042 ms** |

The enormous mapped-byte totals describe sparse virtual extents and Mach COW
object views; they are not eagerly copied resident bytes. This is why the
136 remaps of the nominal 32-GiB arena cost 59.1 ms rather than terabytes of
copy traffic.

The complete private-snapshot stage took 135.299 ms across the two captures,
or 0.995 ms/fork. The measured remap calls explain 79.59% of that stage. The
remaining 27.614 ms covers bank packing, stage-1 alias publication for each
mapping, descriptor construction, and probe overhead. Complete process-spec
construction took 195.642 ms, or 1.439 ms/fork.

The independent runs repeat the same shape:

| Capture | Mapping remaps | Private-snapshot stage | Complete process spec |
|---|---:|---:|---:|
| capture 1 | 50.546 ms | 64.268 ms | 94.072 ms |
| capture 2 | 57.138 ms | 71.031 ms | 101.570 ms |

## Interpretation and decision

The mechanism hypothesis is resolved: the stage is not falling back to an
eager sparse-page copy, and it is not dominated by page-table snapshots. It is
mostly a population of successful Mach COW remaps, led by one sparse arena view
per fork.

A high-water sparse copy for the mmap arena would attack 59.1 ms across these
two runs. Even treating that traced cost as perfectly removable gives about
29.6 ms per cold build, only 0.69% of the 4.27-second measured CPU result. The
entire measured remap population is about 53.8 ms/build, 1.26%; even the entire
private-snapshot stage is about 67.6 ms/build, 1.58%. None reaches the 10%
end-to-end opportunity required before changing address-space behavior.

Therefore no sparse-arena, coalescing, or immutable-sharing behavior candidate
is implemented from this ledger. Those ideas remain valid later cleanups, but
they cannot make Phase 4 green. The next attribution must return to the whole
cold-build CPU/VM-exit surface and find at least roughly 0.43 CPU-second of
opportunity before another optimization is written. The one-VM invariant,
ASID isolation, exact fork/exec output, and writable-private separation remain
unchanged.

## Verification before commit

- Red-first ABI test failed on the missing provider and wrapper declarations,
  then passed after the typed implementation.
- `cargo test -p carrick-observability`: 56 unit tests and 2 doc tests passed.
- `cargo check -p carrick-vmm-hvf`: passed.
- `cargo fmt --all -- --check`: passed after formatting.
- Signed `just build`: passed before both retained captures.
- Both fail-closed captures passed with exact workload output.
- Full `just ci`: passed after both retained captures.
