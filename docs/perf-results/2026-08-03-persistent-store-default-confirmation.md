# Persistent translation store default confirmation

**Date:** 2026-08-03  
**Scope:** Darwin/AArch64 native cold Go build  
**Decision:** **RETAINED; flip the persistent translation store default ON.**
Exact `CARRICK_DSR_PERSISTENT_STORE=0` remains the rollback and controlled-
comparison hatch.

This result supersedes the incomplete campaigns in
[`2026-08-03-store-default-quiet-gate-checkpoint.md`](2026-08-03-store-default-quiet-gate-checkpoint.md).
It does not update Carrick's official Docker ratio by projection; the shipped-
default scoreboard must be measured again after the flip.

## Bound campaign

Campaign `57215-0a2771fe19fc4c948596019cf092edcc` used the same signed binary for
both arms and changed only the host environment:

- source commit: `6821d2ba996deec433c26b0ec86e2c2559e1fbf4`
- executable SHA-256:
  `5ab293b8ca18f1c4791bd92820e2fb4d3d0739e535074c6d7f3913f9b9b46b88`
- Mach-O UUID: `09D5A17A-460D-3701-9528-EB364837BD42`
- image:
  `localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`
- arm A: `CARRICK_DSR_PERSISTENT_STORE` unset (the pre-flip default-off path)
- arm B: `CARRICK_DSR_PERSISTENT_STORE=1`
- schedule: two excluded warmups, then 16 counterbalanced `A1 B1 B2 A2`
  quads (64 measured builds)
- primary metric: `RUSAGE_CHILDREN` total CPU floor
- timeout: 30 seconds per sample; cooldown: 1 second
- power policy: `--allow-battery`; every one of the 17 preflights actually
  recorded AC Power and no thermal/performance warning
- every preflight recorded zero busy-host reasons and zero foreign workloads

The complete campaign is
`target/perf/store-default-confirm/repeated-kick-fix-abba-v1.json`
(SHA-256
`5d90aa7c1d84a8a7fc5be61f53c5d5d5bf20ac69e3992030b7bfcd006b255df2`).
Its immutable arm receipt is
`target/perf/store-default-confirm/repeated-kick-fix-abba-arm/arm.json`
(SHA-256
`887ca886d781c4b2ef9abe6c9f22ea8cfc1b8889d2b137f9cbc70c34465820d9`).
The campaign ran from `2026-08-03T16:47:09Z` to `16:59:32Z`, completed all
66 executions, and recorded zero failed builds, nonzero exits, or timeouts.

## Result

All 16 quads favored store-on for every reported metric.

| metric | store unset | store on | median quad ratio | change | 95% bootstrap ratio |
|---|---:|---:|---:|---:|---:|
| total child CPU | 24.301 s | 22.217 s | 0.9167 | **-8.33%** | 0.9112-0.9204 |
| user CPU | — | — | 0.9249 | **-7.51%** | — |
| system CPU | — | — | 0.8948 | **-10.52%** | — |
| process elapsed | 9959 ms | 9099 ms | 0.9157 | **-8.43%** | 0.9103-0.9214 |
| in-guest workload | 9416 ms | 8567 ms | 0.9116 | **-8.84%** | 0.9061-0.9175 |

For total CPU, the one-sided 95% upper ratio is 0.9197. The sign test is
16/16 candidate wins, `p=1/65536`. The artifact's statistical gate therefore
passes every criterion. Its `retained=false` field is intentional: the generic
runner cannot certify the external mechanism and correctness gates described
below; this document records the coordinator decision after those gates passed.

## Mechanism authority

The win has the expected translation mechanism, not just a timing correlation:

- the v5 hot/cold wire maps cold recovery metadata instead of decoding it on
  every exec;
- a warm `compile` exec replays roughly 8,170 of 8,282 recorded blocks;
- store-on reduces the measured per-exec translate phase from about 50 ms to
  17-18 ms;
- replayed blocks are word-identical to native emission, carry the same trusted
  entries, and patch direct links past the deleted `BindingIndex` guard;
- corrupt/stale wire data fails closed to local translation, and ABI-7/v4 data
  cannot load as ABI-8/v5.

The counter and wire evidence is detailed in
[`2026-08-03-store-v5-lazy-hotcold-wire.md`](2026-08-03-store-v5-lazy-hotcold-wire.md)
and pinned by the mutation-sensitive `native_tap_unit_install` and recorded-
emission identity tests.

## Correctness closure

The earlier store-on failure was real, but it was not a corrupt persisted unit.
DTrace qualified the reported address as a live private JIT-cache PC. Auditing
the async-kick gateway then found the exact race: a second request could arrive
after the first kick captured a translated cache PC but before the signal exit
published phase 2, overwriting the valid kick exit with `KickAtEntry` and
misclassifying the cache PC as a guest PC.

Commit `c2072b42` preserves the first translated-code exit. Its deterministic
regression was red before the fix and green after it. The fixed signed binary
then passed:

- 1,154 serialized `carrick-runtime` library tests (5 ignored);
- all 17 focused kick tests, including the live fused-region async-kick oracle;
- faithful `preemptsigstorm` Carrick-to-Docker differential plus 40/40 direct
  store-on repetitions;
- 64/64 measured store-on cold Go builds plus two warmups
  (`repeated-kick-fix-soak-v1.json`, SHA-256
  `4a12ac3b8aa1ab16454144b308600d2461eba6757e7f0c1b80d6fb05cc58a9ee`);
- native smoke conformance, 23/23 MATCH across Go, CPython, Node, and LTP.

A broad probe invocation initially produced four semantic differences and two
timeouts. It had used up to eight internal workers. The authoritative one-
worker control reproduced the same four semantic differences with the store
**off**, while both timeout probes passed. The identical store-on run produced
the same four differences and the same two passes. Those are pre-existing
native-lane gaps, not store regressions:

- `aliassize`
- `clone3args`
- `execfromthread`
- `recursionguard`

## Default contract

Unset now enables the persistent store. Only exact
`CARRICK_DSR_PERSISTENT_STORE=0` disables it; `=1` remains useful for explicit
candidate arms. Store preparation and replay remain fail-soft: unavailable,
stale, corrupt, or mismatched persisted state falls back to local translation
without weakening guest-visible semantics.

## Shipped-default scoreboard

The required newly signed, serialized Carrick-then-Docker measurement is now
complete. Artifact
`target/perf/store-default-confirm/default-on-native-go-build-v1.json`
(SHA-256
`8fab147f7c6825671123e17cc098ba752194a694e0c467e28590cc435afc9edb`)
binds clean source `2e238aea48da43717b338df22b588d81b056dc3e`, executable
SHA-256
`7e9f25dd7e6bf97aac4cbc90612e02f22090eda02efa2b742aaac41a0852c6fc`,
and the native-arm64 image digest named above. With every performance overlay
unset, five samples per serialized phase measured:

- Carrick workload median: **8,575 ms**;
- Docker workload median: **821 ms**;
- official shipped-default workload ratio: **10.4446x**;
- process elapsed medians: 9,326 ms / 977 ms = 9.5455x.

This supersedes the projected 10.8x figure. The store flip is a controlled
8.84% workload-wall win, but the remaining 10.44x-to-3x gap is still large and
must be attacked through separately attributed mechanisms. The first paired
kernel capture and its causal disqualification are recorded in
[`2026-08-03-default-on-kernel-attribution.md`](2026-08-03-default-on-kernel-attribution.md).
