# Native allocation-owner census and normal opportunity binding

**Date:** 2026-08-03
**Workload:** Darwin/AArch64 native cold `go build`
**Decision:** **STOP — no source-distinct allocation owner clears 10% of total
CPU in both normal-binary bindings**

The lifecycle-complete tagged allocator attributes cumulative requested bytes
from every process image in the cold build, including fork and self-reexec
successors. Two independent feature captures agree closely. Their owner shares
are then bound to two ordinary-binary fault captures and two ordinary untraced
CPU denominators. Even the largest owner, publication recovery, projects to
only **8.3375% / 8.0484%** of total CPU under the deliberately favorable
3,840 ns-per-host-zfod model. No production allocation change is authorized.

This is attribution evidence, not a timing result. Feature timing is discarded,
and traced elapsed time is perturbation metadata only. No optimization was
tested. The official shipped-default cold-build result remains **10.4446x**
native-arm64 Docker.

## Bound authority

All accepted captures used clean source
`80a469da617b0eec4d8e69ee639cbfe287767cfd`, tree
`05a540ce127c897de827b9e29a2c38a5f2620821`, and Linux/arm64 image
`sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`.

The signed feature binary (`--features alloc-owner-census`) was:

- SHA-256 `c46323009b8d944c67dd0692137e1409f57254e18a3ec77cdac19f2e48dbb555`;
- Mach-O UUID `444B9BDA-4565-3E15-8655-6535A4307375`;
- `com.apple.security.hypervisor=true` and `__DATA,__dof_carrick` present; and
- positive for `ALLOCOWNER3`, `translation-orchestration`, and the allocation
  export environment markers.

The source-identical ordinary binary was:

- SHA-256 `a77c7d5243a4d6eaae195d3d8e49bde5b8c46db6eedff9db8db5cf4b2a11e8c0`;
- Mach-O UUID `E0338A4E-19B3-3885-9489-5AE625AD2CE7`;
- the same entitlement and DOF section; and
- negative for `CARRICK_ALLOC_OWNER_CENSUS_DIR` and
  `CARRICK_ALLOC_OWNER_EXEC_EPOCH`.

`RUST_TEST_THREADS=1 just ci` passed before the final captures. The locked
persistent translation store contained 45 files / 42,064 KiB and remained
byte-identical before and after all six accepted runs. Its normalized manifest
SHA-256 was
`135033fbd8c953ba4bc699a89f5aef35fae92221a85693ea04919613d2b4ebbf`.

Host metadata: macOS 27.0 build 26A5388g, Darwin 27.0.0, Mac16,12, 32 GiB,
4 performance plus 6 efficiency logical CPUs. AC power and 100% battery were
recorded as metadata only. `pmset -g therm` reported no thermal, performance,
or CPU-power warning level.

## Coverage fallback and schema history

The strict coverage rule is `other < Q`, with fallback `Q = 0.10` until the
normal opportunity is known. It failed closed twice and caused two deliberate,
one-owner schema refinements:

| schema | accepted structural result | `other` | action |
|---|---:|---:|---|
| v1 | 140 epochs / 71 pids | 13.3776% | add `translation-source-preparation` |
| v2 | 140 epochs / 71 pids | 10.0369% | add `translation-orchestration` |
| v3 A | 140 epochs / 71 pids | **8.7628%** | accept |
| v3 B | 140 epochs / 71 pids | **8.7611%** | accept |

The source names for the refinements came only from the existing DHAT stack
table. DHAT coverage was **36.8376% / 41.6574%** of all-thread translations, so
it is discovery-only and supplies no totals or opportunity claims. It named
`configure_shared_translation` at 491,358,336 / 499,394,240 gross cumulative
bytes and then `ProcessState::translate` at 9,109,059,802 / 10,319,258,502.
Narrower nested scopes take precedence, so `translation-orchestration` receives
only previously residual requests, not the whole gross stack total. The invalid
v1/v2 artifacts remain preserved under `target/perf/alloc-owner-current/` and
are not mixed with accepted v3 evidence.

## Feature captures A/B

Both runs returned zero, emitted exactly one positive `WORKLOAD_NS` and one
`BUILD_OK`, parsed every deterministic `ALLOCOWNER3` record, and left zero
run-id-scoped processes. There were no temporary, malformed, overflow, or
lifecycle-error records.

| coverage | A | B |
|---|---:|---:|
| allocation fragments / process epochs | 140 / 140 | 140 / 140 |
| distinct pids | 71 | 71 |
| NATIVEPERF threads | 440 | 438 |
| all-thread translations | 766,339 | 766,544 |
| total requested bytes | 30,152,321,916 | 30,154,911,601 |
| owner-manifest SHA-256 | `ebff2bfa…42215` | `ad3168d3…9c7f` |
| prebinding report SHA-256 | `7ad7751e…90c7` | `54597324…89f` |

Every owner below is non-overlapping. Calls are `alloc / alloc_zeroed /
realloc`; bytes charge the full successful requested size, not retained or live
memory.

| owner | A bytes | A share | A calls | B bytes | B share | B calls |
|---|---:|---:|---:|---:|---:|---:|
| publication-recovery | 15,729,790,176 | 52.1678% | 766,337 / 0 / 3,722,171 | 15,731,163,936 | 52.1678% | 766,543 / 0 / 3,723,001 |
| publication-map | 4,245,369,872 | 14.0797% | 766,337 / 0 / 2,316,483 | 4,245,902,144 | 14.0803% | 766,543 / 0 / 2,317,061 |
| block-assembler-transient | 3,206,032,324 | 10.6328% | 4,642,695 / 0 / 7,735,560 | 3,206,357,594 | 10.6330% | 4,643,429 / 0 / 7,737,051 |
| other | 2,642,193,020 | 8.7628% | 699,661 / 64,461 / 144,547 | 2,641,903,029 | 8.7611% | 695,972 / 63,635 / 144,749 |
| decode-read-buffers | 1,322,153,094 | 4.3849% | 1,919,379 / 7,613,258 / 682,356 | 1,322,280,292 | 4.3850% | 1,920,020 / 7,614,321 / 682,546 |
| translation-source-preparation | 1,007,103,680 | 3.3401% | 358 / 74 / 0 | 1,007,103,680 | 3.3398% | 358 / 74 / 0 |
| indirect-target-cache | 775,946,240 | 2.5734% | 0 / 370 / 0 | 771,751,936 | 2.5593% | 0 / 368 / 0 |
| publication-indexes | 772,260,544 | 2.5612% | 1,922,896 / 0 / 176,311 | 776,480,056 | 2.5750% | 1,925,010 / 0 / 176,402 |
| translation-orchestration | 383,415,144 | 1.2716% | 2,502,712 / 766,337 / 0 | 383,911,112 | 1.2731% | 2,505,673 / 766,543 / 0 |
| shared-translation-support | 68,057,822 | 0.2257% | 209,273 / 74 / 1,332 | 68,057,822 | 0.2257% | 209,273 / 74 / 1,332 |

## Ordinary fault and CPU bindings

N1/N2 used the authenticated Rust-owned `native-fault` profile at sample
modulus 64. The D program SHA-256 was
`d8bc04989684444ef18a3157392ab3e3e5be55c1661e6cdffd9cd54039e6a860`;
terminal qualification SHA-256 was
`919ee0f898c0402916b6e0fd58bf7e5e3482f2f25dd8bbb7d6b5a05763f24fbc`.
Both completed naturally. Every DTrace drop counter and every identity,
lifecycle, catalog, probe, live-at-end, and pending-fork counter was zero.
For both `as_fault` and `zfod`, ownership sampled-event sums and distinct-page
sums exactly equal the profile's coverage totals: every sampled page joined.

| metric | N1 | N2 |
|---|---:|---:|
| exact `as_fault` | 1,931,940 | 1,930,908 |
| exact `zfod` | 1,531,118 | 1,531,742 |
| exact `cow_fault` | 84,851 | 85,723 |
| sampled host-other `zfod` share | **63.0959%** | **63.1649%** |
| host-other `zfod` repeat factor | 1.00146 | 1.00165 |
| trace elapsed, perturbation only | 28.536 s | 28.691 s |
| raw SHA-256 | `59acd803…8d16` | `bdb32e90…2253` |
| summary SHA-256 | `cd575320…5548` | `1bce6c21…c957` |

C1/C2 ran the exact workload untraced with only `CARRICK_DSR_PROFILE=1`.
`NativePerfEpochAuthority` parsed each full stream; the surrounding allocation
join was intentionally empty, so its only report errors were the 140 expected
missing allocation epochs plus zero allocation bytes. There were no NATIVEPERF
parse or count errors.

| metric | C1 | C2 |
|---|---:|---:|
| process epochs / pids | 140 / 71 | 140 / 71 |
| threads | 436 | 442 |
| all-thread translations | 765,383 | 766,191 |
| supervisor total CPU | **23.211641 s** | **24.081648 s** |
| NATIVEPERF SHA-256 | `78c605ae…11dc` | `fc95ceee…32cc` |

All N1/N2/C1/C2 runs returned zero, printed one positive workload marker and
one `BUILD_OK`, left the locked store unchanged, and had zero scoped survivors.

## Normal opportunity and portfolio

For each binding:

```text
host_other_zfod = exact_zfod * sampled_host_other_zfod_share
host_allocation_cpu_ns = host_other_zfod * 3840
H = host_allocation_cpu_ns / ordinary_supervisor_total_cpu_ns
owner_projected_total_cpu_share = owner_requested_byte_share * H
Q = 0.10 / H
```

The 3,840 ns input is deliberately favorable: it is the old high-end
GOMAXPROCS=10 *all-system-CPU per as_fault* figure, so it charges unrelated
system work to the host allocation opportunity.

| binding | exact zfod | host-other share | estimated host-other zfod | favorable allocation CPU | ordinary CPU | `H` | `Q` |
|---|---:|---:|---:|---:|---:|---:|---:|
| A/N1/C1 | 1,531,118 | 0.630959 | 966,073.238 | 3.709721 s | 23.211641 s | **0.159822** | **0.625698** |
| B/N2/C2 | 1,531,742 | 0.631649 | 967,523.630 | 3.715291 s | 24.081648 s | **0.154279** | **0.648177** |

Both `H` values are finite and inside `(0,1]`. Both final reports are valid,
and `other` is far below the corresponding `Q`. Ranked projections are:

| owner | A projected total CPU | B projected total CPU | smaller projection | verdict |
|---|---:|---:|---:|---|
| publication-recovery | **8.3375%** | **8.0484%** | **8.0484%** | STOP |
| publication-map | 2.2502% | 2.1723% | 2.1723% | STOP |
| block-assembler-transient | 1.6993% | 1.6404% | 1.6404% | STOP |
| other | 1.4005% | 1.3517% | 1.3517% | coverage only |
| decode-read-buffers | 0.7008% | 0.6765% | 0.6765% | STOP |
| translation-source-preparation | 0.5338% | 0.5153% | 0.5153% | STOP |
| publication-indexes | 0.4093% | 0.3973% | 0.3973% | STOP |
| indirect-target-cache | 0.4113% | 0.3948% | 0.3948% | STOP |
| translation-orchestration | 0.2032% | 0.1964% | 0.1964% | STOP |
| shared-translation-support | 0.0361% | 0.0348% | 0.0348% | STOP |

**No owner is CARRY.** Publication recovery is the nearest, but misses the 10%
gate in both independent bindings even under the favorable ceiling. Percentages
are not added: every projection draws on the same bounded fault opportunity.

Final report SHA-256 values are `addf8d3e…4ed8` (A) and
`c42ed308…3f6` (B). The typed binding and complete projection receipts are
`3bf64998…6afb` and `19a0609f…13bb`, respectively. Target-only raw receipts
remain under `target/perf/alloc-owner-current/`.

## Decision and next measurement

Keep the export-only allocator census and strict parser as diagnostics. Do not
change publication recovery/map layout, assembler allocation, decode buffers,
cache sizing, or translation preparation from this evidence.

The next non-regrettable step is a fresh ordinary-binary, tracer-self-excluded
CPU attribution on the current persistent-store default. It must repartition
current user, kernel, dylib, JIT, syscall, and fault time and select the next
source-distinct bucket only if it clears 10% twice. Prior decompositions predate
several retained wins and cannot safely rank the residue. Eager whole-image
translation remains a deferred future design; incremental JIT-on-JIT support
would still be required. Tier D remains default-off pending correctness closure.
