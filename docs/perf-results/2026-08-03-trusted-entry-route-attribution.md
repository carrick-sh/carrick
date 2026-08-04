# Trusted-entry routes are stable but too small to pursue

**Date:** 2026-08-03
**Lane:** Darwin/aarch64 native, shipped-default semantics plus diagnostic route split
**Workload:** cold hello-world Go 1.24 build, fresh `GOCACHE`, `BUILD_OK` required
**Decision:** stop the trusted-entry line; no route reaches the 10% total-CPU opportunity gate

## Result

Two independent, naturally completed 997 Hz captures agree that direct-link
arrival is the dominant route. Their direct-route shares differ by only 0.1703
percentage points, far inside the five-point agreement limit. The route is not
large enough to implement: using the receipt-bound 0.46505 JIT share, direct
arrival projects to 4.17% of total build CPU on average. Even perfect removal
of all three copies of the common trusted-entry sequence projects to only
7.96%.

| measure | capture A | capture B | absolute difference |
|---|---:|---:|---:|
| JIT PC samples | 13,346 | 13,441 | — |
| fall-through sequence samples/share | 6 / 0.2614% | 9 / 0.3928% | 0.1314 pp |
| direct sequence samples/share | 1,204 / 52.4619% | 1,198 / 52.2916% | **0.1703 pp** |
| indirect sequence samples/share | 1,085 / 47.2767% | 1,084 / 47.3156% | 0.0389 pp |
| projected direct total CPU | 4.1954% | 4.1450% | 0.0504 pp |
| projected indirect total CPU | 3.7808% | 3.7506% | 0.0302 pp |
| projected all-route total CPU | 7.9971% | 7.9267% | 0.0704 pp |

The mean projections are 0.0260% fall-through, **4.1702% direct**, 3.7657%
indirect, and **7.9619% for all routes combined**. The decision rule therefore
rejects every route without a production candidate. The earlier 12.2% common
sequence projection was a useful hypothesis, but the exact route-bounded join
supersedes it.

## Capture validity

Both capture roots were new and had distinct isolated translation stores. Each
protocol ran an untraced warmup before the traced workload, left the persistent
enable variable unset (the shipped default), set only the isolated store,
route split, and retirement export controls, and then verified the same store
authority before and after tracing.

| contract | capture A | capture B |
|---|---:|---:|
| `BUILD_OK` warmup/traced | yes / yes | yes / yes |
| target completed naturally | yes | yes |
| DTrace drops/errors/interruption | 0 / 0 / false | 0 / 0 / false |
| matched / missing PID / missing range | 13,346 / 0 / 0 | 13,441 / 0 / 0 |
| fork-inherited samples resolved by authenticated lineage | 0 | 2 |
| owned / unit-replay route spans | 765,152 / 459,439 | 764,379 / 459,198 |
| owned / unit-replay route samples | 1,718 / 577 | 1,713 / 578 |
| store payload count, pre/post | 11 / 11 | 11 / 11 |
| store payload bytes, pre/post | 45,637,774 / 45,637,774 | 45,488,571 / 45,488,571 |

The owned and unit-replay origin counts prove that the live join covered both
native emission and persistent-unit replay rather than extrapolating one from
the other. Capture A's store authority was device 16777231, inode 28668346,
SHA-256 `c518f02d148b0864f57add4d3c09dfaba481092d4c840c2e827bbf1c40558226`;
capture B independently used inode 28668560 and SHA-256
`526e80089cb3741fba361ade5ad95c776774fa87e0fe36b738ce6accd4c71580`.

The traced workload times (A 16.123 s, B 16.136 s) are deliberately
**non-citable**: the profile is perturbing, and only same-instrument sample
shares are used. The untraced warmups are protocol setup, not a baseline. The
official shipped-default cold-build ratio remains the separate five-sample
10.4446x result.

## Provenance

- source commit: `d8856374dc6e76a4aa5440ef959a6ac77547aea5`, clean
- signed binary SHA-256:
  `f45da9e35b1a0c5aa2cd58899584c26c4d88a18628916d82287ce138cb64e036`
- Mach-O UUID: `B3BF0641-FF18-3B83-810C-3D1D98CFC346`
- signature: `codesign --verify --verbose=2` valid and satisfies its Designated Requirement
- DOF: `otool -l` contains `__DATA,__dof_carrick`
- D program SHA-256:
  `e40134bb81e4a6471f4fed81a53c961816f64b2f54a7a577171fc220905daf7e`
- image: `localhost:5005/carrick-go-conformance:1.24`, arm64,
  `sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`
- host: Mac16,12, 4 performance + 6 efficiency cores, macOS 27.0 build 26A5388g
- every preflight: no foreign Carrick workload, no Docker oracle, no active
  compiler, no thermal/performance/CPU-power warning; AC power recorded as
  metadata only. A transient `mediaanalysisd` burst was observed and allowed
  to finish before capture A began. Accepted samples showed roughly 91-94%
  aggregate idle CPU and no background process occupying a full core.

### Evidence identities

| artifact | capture A SHA-256 | capture B SHA-256 |
|---|---|---|
| raw trace | `a9fabbcec1459cef1449784dd422980bf899406108a8f2d15687f18f370e1274` | `114acfad0878a267cf29d62695718df073fa8e1f5688156f34bf19e38826f692` |
| capture receipt | `237253c1dd6e69836f65ad40ea29b6d228259be25bf74d5ad671bb634b816489` | `8cb89e9617826781ff6be9e7318b40d41f41780f123e5e52a1e4629b8010fdfc` |
| census report | `eaa4ab0d20c62fe3d2b40978193e47e6914a542ec7bf9c372bddcdf2176f2984` | `ae08cdc58e5664557047e6bd7df6b796079c911d33508648c4cca7819fa9027e` |
| snapshot manifest | `c2929ac137e3c755ddf32aaa759c8d153fa977d7d2fa2c8567576b3fd6da1d4b` | `6e73708b4532d9527a596a920ff74b0859184a7f3c5c282a79b43dfceb879231` |
| store manifest, pre/post | `584f2258fe695102fe99a54b2fbb51dc459823a756b8bc14e169569dae246bde` | `a5a14b95444755d9372e33c42615bcaa52171dd795990c2c670e649622abbf3a` |
| warmup receipt | `6dc546fc43eae5bf8d9382cf06c4d0436b557bacba6d8a6d050dee31962a3d81` | `33810c5bbf2da37f5851a2fde131c734a3f22794ff389b62a68808022a0991f0` |

Raw artifacts remain under
`target/perf/trusted-route-attribution-{a,b}-d8856374/` and are intentionally
not committed.

## Instrument corrections retained as evidence

The first attempted capture correctly failed closed: the old broad
"not-main-Mach-O/shared-cache" predicate admitted 9,296 host-text samples and
20 orchestrator samples. Exact `dsr-cache-bounds` reduced the PC population to
the JIT range. A later one-sample failure exposed fork children executing the
inherited parent cache before publishing their replacement range. The final D
program emits parent/child lineage, and the Rust join permits ancestry fallback
only when the child has its own retirement snapshot and the sampled PC resolves
uniquely in a recorded ancestor snapshot. Capture B exercised that path with
two samples. These rejected attempts are mechanism-debugging receipts, never
part of the decision.

## Cleanup and next work

The route-copy emitter, route-specific routing, capture/census CLI, and
diagnostic environment controls are removed after this decision. The ordinary
emitter source is restored byte-for-byte to the pre-diagnostic version. The
three pre/post SHA-256 identities are `emit.rs`
`1dc932cc27cebb859dc937963634f518643228dd144fd400764bcf365c30ba0c`,
`artifact_spike.rs`
`82b1592f8cb434687cec7abebcfc4550da7f61a675a4add09b39a11691349632`,
and `translator.rs`
`7c3bdf46717f26b2f3e6ae6c66b7c997d1a09554bf7fd33465126e9293fd2f02`.
The improved D script remains a durable artifact at SHA-256
`e40134bb81e4a6471f4fed81a53c961816f64b2f54a7a577171fc220905daf7e`,
but no production hot path depends on it.

Post-cleanup verification passed 219/219 AArch64 DSR tests, 1,154 runtime
tests with five intentional ignores, 20/20 trace-profile integration tests,
157/157 CLI unit tests, and the full serialized `RUST_TEST_THREADS=1 just ci`
gate. The final uninstrumented signed release binary has SHA-256
`a6bb3969ec593bfb0e0271087fc9edbac4943dd2cce33a984536df5b35ae9d49`,
Mach-O UUID `6A228EC6-3600-3101-BC35-8A04968BA4FC`, a valid signature satisfying
its Designated Requirement, and the `__dof_carrick` section; no diagnostic
environment or schema marker remains in it.

The next attribution target is the already-approved **process exec/exit
amplification**: bind untraced Rust-owned lifecycle counters to both the cold
build and 20-exec workload, and pursue a change only if it clears the same 10%
end-to-end gate. If that workload crashes or silently loses a process, timing
interpretation stops and `carrick debug lldb-run`/a saved core plus the exported
always-on event ring is the authority. Eager full-image translation remains a
deferred future improvement; it would not replace incremental translation for
JIT-on-JIT code.

## Confidence

- **Very high (99%)** that the two captures are lossless and fully joined: all
  drop/error/coverage counters are zero and both workloads reached `BUILD_OK`.
- **High (97%)** that route shares are stable: the same route dominates and
  differs by only 0.1703 percentage points across independent stores.
- **High (95%)** that no trusted-entry route supports a >=10% total-CPU
  candidate: the largest is 4.17%, and even all routes together are 7.96%.
- **High (95%)** that the official 10.4446x shipped-default ratio is unchanged:
  traced timing was not substituted for a clean baseline and the diagnostic is
  removed rather than shipped.
