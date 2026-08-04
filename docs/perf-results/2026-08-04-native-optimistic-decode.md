# Native optimistic decode: stopped hypothesis

**Date:** 2026-08-04

**Lane:** Darwin/AArch64 native DSR, shipped-default controls

**Decision:** do not retain the decode-outside-writer implementation

## Question and decision

The experiment asked whether pure block decode and planning could run outside
the process-wide translation writer, with a short locked commit that
revalidated generation and publication authority. The intended mechanism moved
material wait time off the exclusive writer, but the same-workload retention
gate measured a decisive product regression. The implementation was therefore
reverted. The reviewed discard diagnostics and their fail-closed parser remain
because they accurately expose duplicate optimistic work for future concurrency
experiments.

The official serialized Carrick/Docker cold-build scoreboard remains
**10.1776x**. This experiment produced neither a retained candidate nor a fresh
serialized Carrick-then-Docker refresh, so none of its wall measurements replace
that authority.

## Source, binary, workload, and control authority

The implementation consisted of:

- `3733eeef` — `perf(native): decode blocks outside process writer`
- `9e0b0817` — `fix(native): account failed optimistic decodes`

The candidate measurement source was
`9a2788d6eb8f4c29f4ea5df23b2fc38866d2d39d`; its runtime implementation tip was
`9e0b08178b9335f03825001a56190a6e1b375837`. Commit `9a2788d6` changed only the
reviewed offline validator after the runtime binary was frozen. The candidate
signed binary SHA-256 was
`1809ca3782184437b2e623b22a555ec5c5af08a40182697b6f8f6f78da148f06`.

The exact ABBA control source was
`a5bd497187785c5756cf8f10e8d92b5e7287d779`; its signed binary SHA-256 was
`752a0b2bc7cb5288dbd9594a31c4c3ca958776533b56255afe6cfaf5a7f0b000`.
The control and candidate arm-receipt SHA-256 values were respectively
`072a39a46535e7bcfa438819194c81acdfac54fe9c9372e065769bfb3bb9edb1`
and `d4c245eb258dd569cbde58fbc8978d47dacd28fd765b3e0a29de864866b7e7d4`.
Both arms passed strict codesign verification, carried the hypervisor
entitlement, exposed a loadable `__dof_carrick` section, used the same toolchain,
and had clean source receipts.

Both arms used the immutable arm64 image
`localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`
and `scripts/perf/overlays/native-default.json`, SHA-256
`82fc1fb6cec6eebeb0f4a301d9a197c4f5771739a81cb0907ed8adeb42cd1d31`.
That overlay cleared the experimental store, profiling, artifact, and shared-
store controls on both arms.

## Untraced NATIVEPERF mechanism screen

`scripts/perf/native_go_dtrace_target.py --variant default
--mechanism-profile` produced two serialized cold-build captures using the
candidate runtime binary. Both returned exactly one `BUILD_OK`, parsed as v5
with 453 complete groups and zero invalid records, and passed the reviewed
validator at `9a2788d6`.

| Measurement | A | B |
|---|---:|---:|
| workload wall | 8.645644250 s | 8.627243292 s |
| translations | 767,786 | 768,023 |
| all-attempt decode elapsed | 2.870025569 s | 2.816131528 s |
| optimistic decode discards | 66,897 | 64,905 |
| discarded-decode elapsed | 0.578737068 s | 0.546417578 s |
| plan elapsed | 0.020447497 s | 0.020490922 s |
| emit elapsed | 3.309502628 s | 3.289557635 s |
| publication elapsed | 0.905773948 s | 0.899258961 s |
| successful translation elapsed | 8.351706064 s | 8.332095879 s |
| supervisor total CPU gauge | 23.750932 s | 24.857812 s |
| discard count / translations | 8.7130% | 8.4509% |
| discard elapsed / all decode elapsed | 20.1649% | 19.4031% |

The phase values are summed per-operation `Instant` durations, not CPU
counters. Their ratios to the supervisor CPU gauge are cross-unit diagnostics,
not CPU-share claims. They established that duplicate decode was measurable and
bounded enough to continue to the authoritative ABBA gate; they did not prove a
product win.

| Target-only artifact | SHA-256 | Producer and semantics |
|---|---|---|
| `profile-A.out` | `1f20b0dc8664ce6904767aebc01cfffaa6db65d5d221f6620654c83585c11283` | candidate binary, workload protocol stdout |
| `profile-A.log` | `67e33b3f6c157fbf1eabd3c1baf03d4d4e3fc722663393363f8d87cfd053b3b8` | candidate binary, NATIVEPERF v5 stderr |
| `profile-B.out` | `76761d81aa685bf4993dde0a2a5e9d8a3edf17494b0340dd0ed71a8ff6549be7` | candidate binary, workload protocol stdout |
| `profile-B.log` | `006522bafe9419f5a0739934a4588abdb82e082ea20e4cc95fc3d2b9eb3dadfe` | candidate binary, NATIVEPERF v5 stderr |

## Qualified DTrace mechanism attribution

Two accepted typed `carrick trace --profile native-wall` captures, A2 and B,
were produced by the candidate binary. Both completed naturally with
`complete=true`, `bounded=false`, an authenticated header, accepted live kernel
symbol overlay, and zero probe errors, drops, incomplete pairs, overflows, or
lifecycle/range/identity violations. The paired offline attribution accepted
both profiles and their stability comparison.

| Target-only artifact | SHA-256 | Producer and semantics |
|---|---|---|
| A2 raw trace | `8b9e6eda8286859d52da75277a8273dc55b720c5472826c4a4ef698dd7404969` | candidate binary, authenticated typed native-wall stream |
| A2 summary | `eced3f87c05240cc6ffdd739b01985651c8df6de306992af237c88ee20e187a1` | candidate binary and current typed parser, 46,148 rows |
| B raw trace | `be1b3278af59db46f84efea610464b4a257046f93bee7773237837e0555d4ba8` | candidate binary, authenticated typed native-wall stream |
| B summary | `c0f312154da222ac4f2500036899c31d0c9a12ff795f41634dc8b11a5a7dadae` | candidate binary and current typed parser, 42,281 rows |
| paired attribution | `b44fb5d2d41ea869bc105ae34ede55598874196d1f16640ded989ff44416b3e6` | `native_wall_attribution.py`, exact candidate binary binding |

Using all same-instrument CPU samples as the denominator, total
`psynch_cvwait` share fell from the retained old pair's 15.1508% / 15.2155% to
12.0372% / 12.2176%, a 19.4-20.9% relative reduction. Row-local ASLR
symbolization against each capture's matching binary put the strict adjacent
leaf-to-root stack
`RawRwLock::lock_exclusive_slow -> ThreadTranslator::translate_read_mostly` at
12.2647% / 12.0286% before and 8.6228% / 8.8257% after, a 26.6-29.7% relative
reduction.

This is mechanism-only evidence. The retained old traces built a small program
that imported `fmt`; A2/B built the approved minimal `println` program. The
instrumentation was highly perturbing, and sample-share movement was never used
as a CPU-seconds retention claim.

## Same-workload ABBA retention gate

`scripts/perf/native_go_build_abba.py` produced
`target/perf/native-optimistic-decode/abba-v1.json`, SHA-256
`5e88d50dc10308b56d76984146391fe77e1e8dda790303cd6ae37330ea2c1f05`,
from the exact source/binary/image/overlay receipts above. The schedule was two
excluded warmups followed by eight A-B-B-A quads. The artifact was complete and
accepted: 34/34 samples returned zero with `BUILD_OK`, 32/32 measured samples
were included, all 9/9 preflights were clean, and timeout, capture, execution,
cleanup, remaining-process, foreign-workload, Docker-oracle, thermal, load, and
identity-drift counts were all zero.

| Metric | Candidate/control median ratio | Two-sided 95% interval | Candidate wins |
|---|---:|---:|---:|
| total child CPU | **1.137399** | **[1.124574, 1.146825]** | 0/8 |
| child user CPU | 1.112970 | [1.102824, 1.122284] | 0/8 |
| child sys CPU | 1.218661 | [1.193188, 1.225041] | 0/8 |
| workload wall | 1.014402 | [1.005370, 1.022172] | 0/8 |
| outer elapsed | 1.013906 | [1.004053, 1.021717] | 0/8 |

For every metric, the candidate-favorable one-sided sign probability was 1.0.
Eight losses in eight non-tied trials give a regression-direction one-sided
probability of `1/256 = 0.00390625` and exact two-sided extreme probability of
`2/256 = 0.0078125`.

The targeted writer-wait mechanism genuinely fell, but product CPU rose 13.74%
and system CPU rose 21.87%. Reducing a wait stack therefore did not reduce
product CPU. Duplicate decode, changed runnable concurrency, and induced Darwin
kernel work are plausible contributors, but the precise additional-cost root
cause remains inferred rather than proven. No further root-cause claim is
needed for the no-retain decision.

## Revert and preserved diagnostics

The losing implementation was reverted in dependency-reverse order:

- `99ce4d0c` reverts `9e0b0817`
- `89e82b84` reverts `3733eeef`

At restored source `89e82b84`, the three implementation files are byte-
equivalent to the reviewed diagnostics-only tree at `d4c84088`. The retained
commits are:

- `d4c84088` — typed `optimistic_decode_discards` and
  `optimistic_decode_discard_ns` diagnostics; naturally zero on the restored
  serialized path
- `9a2788d6` — fail-closed parser semantics for all-attempt decode and typed
  discard time
- `d2177d1d` and `196860ee` — design and execution plan

## Restored-tree verification

The following fresh gates ran after both reverts and before this document was
committed:

- `cargo test -p carrick-dsr --lib profile -- --nocapture`: 16 passed
- `cargo test -p carrick-dsr-aarch64 --lib translator::tests -- --nocapture`:
  38 passed
- serialized runtime native-DSR filter: 153 passed, 5 intentional opt-in
  ignores
- strict Python mechanism suites: 165 passed
- focused Clippy with `-D warnings`: pass
- `cargo fmt --all -- --check`: pass
- `RUST_TEST_THREADS=1 just ci`: pass, including 1,164 runtime tests with 5
  intentional ignores, 296 runtime integration tests, and 17 process-syscall
  integration tests
- `just build`: pass; restored signed binary SHA-256
  `82572dd3f7da5f2a4252782038f2c52bec8b30f6cdd7f1fc3a121f13ccceae51`;
  strict codesign, hypervisor entitlement, and loadable `__TEXT,__dof_carrick`
  verified
- `just conformance-native smoke`: 23/23 MATCH, 23 cached oracle results, zero
  live Docker oracle runs, no regressions

## Future boundary

Eager whole-image translation remains a deferred future improvement. It might
amortize publication for eligible immutable image code, but it cannot replace
incremental translation because JIT-on-JIT and dynamically generated code still
need the incremental path. The next production candidate must instead begin
with fresh attribution of the current retained tree and clear the campaign's
10% opportunity bar before implementation.
