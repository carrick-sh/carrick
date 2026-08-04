# Current-default native fault ownership and publication-memory binding

**Date:** 2026-08-03  
**Workload:** Darwin/AArch64 native cold `go build`  
**Decision:** **STOP — the named translation-publication memory mechanism does
not clear the 10% total-CPU gate in either accepted binding**

Two source-identical `native-fault` captures establish that ordinary Carrick
host allocations, not guest-owned mappings, dominate current-default zero-fill
faults. Two separate export-only Rust censuses then bind the largest known
source to translation publication: initialized PC maps and recovery tables plus
the JIT bytes written for the same blocks. The fault ownership and the source
census both reproduce closely, but the deliberately favorable opportunity
projection is only **7.411% / 7.425%** of total cold-build CPU. No production
memory change is authorized.

This is mechanism evidence, not a timing result. DTrace roughly tripled the
workload window, so its elapsed time is retained only as perturbation metadata.
The official shipped-default cold-build ratio remains **10.4446x**.

## Bound authority

All four accepted captures used clean source
`0e35a2d37b8f74acdb83c245f5fcfe7257f892b3`, tree
`b6e38c37b4fabd690da6036250759b0b2c86296c`, and the same signed executable:

- SHA-256: `813201a8f0b71f495c2771b7e2deee941c1c6ec9832aca0bf7d571be7f065819`
- Mach-O UUID: `407C0AF5-5880-3A2F-816F-5CBDA63CBB42`
- strict code-sign verification: valid
- entitlement: `com.apple.security.hypervisor=true`
- `__DATA,__dof_carrick`: present
- bundled D program SHA-256:
  `d8bc04989684444ef18a3157392ab3e3e5be55c1661e6cdffd9cd54039e6a860`
- launch-birth qualification SHA-256:
  `c95d4df83d3fadb4abf2bebe1dd53778e351c89e5c0cdba084bc8e641faaf503`
- terminal qualification SHA-256:
  `919ee0f898c0402916b6e0fd58bf7e5e3482f2f25dd8bbb7d6b5a05763f24fbc`

`RUST_TEST_THREADS=1 just ci` passed before `just build`. The workload image was
Linux/arm64
`sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`.
The isolated persistent store contained 45 files / 42,064 KiB and remained
byte-identical before and after every run; the manifest SHA-256 was
`135033fbd8c953ba4bc699a89f5aef35fae92221a85693ea04919613d2b4ebbf`.

Host metadata: macOS 27.0 build 26A5388g, Darwin 27.0.0, Mac16,12, 32 GiB,
4 performance plus 6 efficiency logical CPUs. AC power and a charged battery
were recorded as metadata only; they did not gate acceptance. `pmset -g therm`
reported no thermal or performance warning level.

## Fault captures A/B

Both captures returned zero, printed exactly one positive `WORKLOAD_NS` and one
`BUILD_OK`, completed naturally, and left zero run-id-scoped Carrick processes.
Every DTrace drop counter and every identity, lifecycle, catalog, probe, live,
and pending-fork violation counter was zero. Every sampled page joined to one
authenticated process birth and complete owned-range catalog.

| metric | A | B |
|---|---:|---:|
| exact `as_fault` | 1,930,155 | 1,943,036 |
| exact `zfod` | 1,532,367 | 1,540,269 |
| exact `cow_fault` | 84,169 | 87,202 |
| guest-owned share of sampled `zfod` | 36.7885% | 37.2605% |
| host-other share of sampled `zfod` | **63.2115%** | **62.7395%** |
| host-other `zfod` repeat factor | 1.00638 | 1.00146 |
| trace elapsed, perturbation only | 27.685 s | 26.795 s |
| raw SHA-256 | `a32bd277…5dfa5` | `2f19bb3…6a05` |
| report SHA-256 | `1560233…abe5` | `2e4d1f9…7d25` |

The exact fault totals differ by 0.67% (`as_fault`) and 0.52% (`zfod`). The
host-other zfod shares differ by 0.472 percentage points. Near-one host-other
repeat factors show a first-touch/retained-allocation shape, not repeated
refault churn.

## Source binding D/E

Because host-other dominates, the source binding uses the existing translation
census rather than inferring a call site from address shape. The export was
extended to record, at process exit and exec handoff, each publication's
private/unit block identity, JIT bytes written, initialized and retained
capacity bytes for its owned PC map and recovery table, and transient direct
link capacity. The strict Rust reader rejects unknown fields, truncation,
initialized length above capacity, inconsistent totals, dangling segments, and
incomplete process coverage.

Accepted runs D and E each reconciled **140/140** independently parsed
NATIVEPERF v5 process-image epochs, 71 pids, zero missing re-exec successors,
zero sequence anomalies, zero flush imbalance, and no failed census files.
One earlier run C was deliberately rejected from the accepted pair because an
`atexit` backstop caught one 536-byte translation after an explicit exit flush,
producing `flush_balance=-1`. Its payload was not needed for the result.

| source counter | D | E | E/D drift |
|---|---:|---:|---:|
| private blocks | 765,996 | 766,363 | +0.0479% |
| unit blocks | 450,521 | 450,578 | +0.0127% |
| JIT bytes written | 618,724,660 | 618,929,828 | +0.0332% |
| initialized PC-map bytes | 1,583,891,824 | 1,584,657,840 | +0.0484% |
| initialized recovery bytes | 5,289,575,832 | 5,292,349,704 | +0.0524% |
| initialized owned metadata | **6,873,467,656** | **6,877,007,544** | **+0.0515%** |
| retained metadata capacity | 10,228,702,208 | 10,234,005,888 | +0.0519% |
| spare retained capacity | 3,355,234,552 | 3,356,998,344 | +0.0526% |
| direct-link capacity, transient | 102,929,472 | 102,963,712 | +0.0333% |
| NATIVEPERF total CPU | 23.693980 s | 23.662522 s | -0.1328% |
| untraced workload window | 8.646791 s | 8.577344 s | -0.8031% |

Recovery entries are 76.96% of initialized owned metadata in both runs. The
3.36 GB of spare capacity is retained virtual/heap capacity, not evidence that
those bytes were initialized or faulted, so it is excluded from the opportunity
numerator. Transient direct-link *capacity* is excluded for the same reason.

Raw target-only receipts live under
`target/perf/native-fault-current-0e35a2d3/{A,B,D,E}`. The accepted Rust report
SHA-256 values are `5c83eba…c29be` (D) and `9e28782…9a633` (E); the independent
NATIVEPERF denominator receipts are `7120177…4ffa` and `e1805ff…8c50`.

## The 10% gate

The source-distinct numerator is deliberately generous: every initialized
owned-metadata byte plus every JIT byte written by the same publication path.
That is 7,492,192,316 / 7,495,937,372 bytes, or 457,288 / 457,516 complete
16 KiB pages after rounding up. It is 29.842% / 29.704% of exact zfod events
and 47.206% / 47.468% of the sampled-and-scaled host-other zfod estimate.

Two independent favorable projections remain below the gate:

| projection | D/A | E/B |
|---|---:|---:|
| written pages × **3.84 us/fault** / current total CPU | **7.4111%** | **7.4247%** |
| written pages / exact `as_fault` × **32.4% kernel CPU** | **7.6761%** | **7.6290%** |

The 3.84 us input is the older GOMAXPROCS=10 *all-system-CPU per as_fault*
figure. Charging all of it to these source pages is intentionally favorable:
it includes non-fault system work and is the high end of the measured
1.81-3.84 us range. The second route likewise spreads the whole current kernel
bucket proportionally across `as_fault` events. Neither route is a lower-bound
win, and both still miss 10% in both bindings. Untallied allocator/reallocation
churn cannot be assumed into existence to authorize a runtime patch.

**Decision: STOP this production hypothesis.** Keep the exact export and Rust
reader as diagnostics; do not change PC-map/recovery semantics, allocation, or
publication layout from this evidence. A separate user-CPU mechanism could be
reopened only after source-owned counters independently bind it above 10%.

## Next measurement

Host-other remains the dominant zfod class, but the named publication bytes
explain only about 47% of its scaled event population. The next measurement is
therefore the **residual host-allocation first-touch source**, not a speculative
metadata rewrite: add export-only cumulative allocation/initialization counters
at source-distinct owners, close them at exec/exit, and apply the same two-run
10% gate. Lifecycle export is the accepted interface for now; a core-file
decoder for these counters is a future diagnostic improvement, while the
always-on event ring remains the crash path for process/fork/exec history.

Eager whole-image translation remains explicitly deferred. It could amortize a
full eligible image up front, but JIT-on-JIT still requires incremental
translation, and this campaign does not reopen that design without a higher
confidence opportunity.
