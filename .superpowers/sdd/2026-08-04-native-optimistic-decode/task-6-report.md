# Task 6 report: optimistic-decode eight-quad retention gate

## Verdict

**VALID EVIDENCE, DO NOT RETAIN THE CANDIDATE IMPLEMENTATION.** The official
two-warmup plus eight-quad A-B-B-A campaign completed and was accepted as
measurement evidence. All 34 samples returned zero, emitted `BUILD_OK`, avoided
timeouts and capture/execution errors, and cleaned up successfully. Both
warmups were excluded and all 32 measured samples were included. All nine
preflights reported no foreign Carrick/compiler/spin/DTrace workload, no Docker
oracle, the exact image and arm receipts, clean source identities, and no
thermal or load failure.

The candidate is a statistically resolved regression on every supported
metric. The primary paired total-child-CPU median ratio is **1.137399**
(candidate/control), with two-sided 95% interval
**[1.124574, 1.146825]**. The candidate lost all eight CPU quads. Workload wall
is also resolved as a regression: **1.014402 [1.005370, 1.022172]**. This fails
the brief's retention rule decisively.

Task 6 modified no tracked source, did not push or move `main`, and did not
revert anything. The controller should preserve the design, plan, diagnostic
schema/parser work, reviewed evidence, and immutable Task 6 receipts, while
reverting only the losing implementation commits after confirming the exact
dependency-safe revert set.

## Source, binary, image, and receipt authority

The named detached control worktree did not exist at preflight and was created
without deleting or overwriting any worktree:

```text
control worktree: /Volumes/CaseSensitive/carrick/.worktrees/native-optimistic-control
control commit:   a5bd497187785c5756cf8f10e8d92b5e7287d779
control branch:   detached
control status:   clean

candidate worktree: /Volumes/CaseSensitive/carrick/.worktrees/native-store-default
candidate commit:   9a2788d6eb8f4c29f4ea5df23b2fc38866d2d39d
candidate branch:   codex/native-store-default
candidate status:   clean
runtime implementation tip: 9e0b08178b9335f03825001a56190a6e1b375837
later source: 9a2788d6eb8f4c29f4ea5df23b2fc38866d2d39d (reviewed Python-only validator repair)
```

Both arms used the exact immutable image:

```text
localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b
architecture: arm64
image ID: sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b
```

Both used the same `scripts/perf/overlays/native-default.json` file, SHA-256
`82fc1fb6cec6eebeb0f4a301d9a197c4f5771739a81cb0907ed8adeb42cd1d31`.
The overlay explicitly cleared every listed experimental variable, including
`CARRICK_DSR_PERSISTENT_STORE` and all profile/artifact/shared-store toggles.

| Identity | Control | Candidate |
|---|---|---|
| source | `a5bd497187785c5756cf8f10e8d92b5e7287d779` | `9a2788d6eb8f4c29f4ea5df23b2fc38866d2d39d` |
| binary SHA-256 | `752a0b2bc7cb5288dbd9594a31c4c3ca958776533b56255afe6cfaf5a7f0b000` | `1809ca3782184437b2e623b22a555ec5c5af08a40182697b6f8f6f78da148f06` |
| receipt SHA-256 | `072a39a46535e7bcfa438819194c81acdfac54fe9c9372e065769bfb3bb9edb1` | `d4c245eb258dd569cbde58fbc8978d47dacd28fd765b3e0a29de864866b7e7d4` |
| Mach-O UUID | `FD5B8B56-5D38-34A6-A420-AED2B1AC5515` | `87630F25-6302-3159-BEDB-46F5D28147F7` |
| entitlement SHA-256 | `c439c3ffbe9d1b486321de3360bd9f1368024751553ae131aa0490e4e49841dd` | same |
| strict codesign verification | pass | pass |
| loadable `__dof_carrick` | present | present |
| receipt mode | `0444` | `0444` |
| source receipt | clean, detached | clean, named branch |
| toolchain | `rustc 1.96.0 (ac68faa20 2026-05-25)` | same |

The candidate arm rebuild reproduced the required pre-ABBA binary SHA exactly;
the live candidate binary and frozen candidate-arm binary both remained
`1809ca...f06`.

## Commands and preflight

The quiet-box/source preflight used read-only process, repository, power, and
worktree checks before creating anything:

```bash
git -c core.fsmonitor=false rev-parse HEAD
git -c core.fsmonitor=false status --short
shasum -a 256 target/release/carrick
git worktree list --porcelain
pgrep -alf '(^|/)(carrick|dtrace|Docker|docker|native_go_build_abba|native-wall|dtruss)( |$)'
docker ps --format '{{.ID}} {{.Image}} {{.Names}} {{.Status}}'
uptime
pmset -g batt
pmset -g therm
```

There was no Carrick, DTrace, compiler, ABBA, or performance workload. The only
Docker container was the long-lived `vt-ferry-registry` required to serve the
exact image; no Docker oracle ran. The host was on AC power with a charged 100%
battery and no recorded thermal/performance/CPU-power warning. Battery was
explicitly allowed by the user but was not needed by the observed AC-powered
campaign. The harness retained every other mandatory gate.

The exact control preparation was:

```bash
git worktree add --detach \
  /Volumes/CaseSensitive/carrick/.worktrees/native-optimistic-control \
  a5bd4971
git -C /Volumes/CaseSensitive/carrick/.worktrees/native-optimistic-control \
  -c core.fsmonitor=false status --short
git -c core.fsmonitor=false status --short

just \
  -f /Volumes/CaseSensitive/carrick/.worktrees/native-optimistic-control/justfile \
  -d /Volumes/CaseSensitive/carrick/.worktrees/native-optimistic-control \
  build
```

The control build completed and signed successfully. Both immutable arms were
then prepared with the exact brief commands:

```bash
python3 scripts/perf/native_go_build_abba.py prepare-arm \
  --source-repo /Volumes/CaseSensitive/carrick/.worktrees/native-optimistic-control \
  --destination target/perf/native-optimistic-decode/control-arm \
  --label retained-a5bd4971 \
  --role control \
  --image localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b

python3 scripts/perf/native_go_build_abba.py prepare-arm \
  --source-repo "$PWD" \
  --destination target/perf/native-optimistic-decode/candidate-arm \
  --label optimistic-decode-tip \
  --role candidate \
  --image localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b
```

Neither arm destination nor the ABBA output existed before its producing
command. Existing Task 5 target artifacts were preserved. The official command
was then run alone and allowed to complete without intervention:

```bash
python3 scripts/perf/native_go_build_abba.py run \
  --harness-repo "$PWD" \
  --control-receipt "$PWD/target/perf/native-optimistic-decode/control-arm/arm.json" \
  --candidate-receipt "$PWD/target/perf/native-optimistic-decode/candidate-arm/arm.json" \
  --control-overlay "$PWD/scripts/perf/overlays/native-default.json" \
  --candidate-overlay "$PWD/scripts/perf/overlays/native-default.json" \
  --quads 8 \
  --cooldown-seconds 2 \
  --timeout-seconds 30 \
  --allow-battery \
  --image localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b \
  --output "$PWD/target/perf/native-optimistic-decode/abba-v1.json"
```

Campaign identity:

```text
campaign ID: 22775-2103a32a62bb4cc8b2daee434b192ffe
started:     2026-08-04T15:34:01.114882+00:00
finished:    2026-08-04T15:40:47.446296+00:00
artifact:    target/perf/native-optimistic-decode/abba-v1.json
artifact SHA-256: 5e88d50dc10308b56d76984146391fe77e1e8dda790303cd6ae37330ea2c1f05
schedule: excluded-a-b-then-a1-b1-b2-a2-v1
```

## Acceptance gate

| Gate | Result |
|---|---:|
| complete / accepted evidence | true / true |
| samples | 34/34 |
| excluded warmups | 2/2 |
| measured samples | 32/32 |
| measured `BUILD_OK` | 32/32 |
| all-sample return code zero | 34/34 |
| timeouts | 0 |
| capture errors | 0 |
| execution errors | 0 |
| cleanup nonzero / remaining Carrick processes | 0 / 0 |
| preflights | 9/9 |
| busy-host reasons | 0 |
| foreign workload processes | 0 |
| Docker oracles | 0 |
| image/source/binary/overlay/receipt drift | 0 |
| thermal/load failures | 0 |

Here, `accepted=true` means the evidence artifact passed its validity gates. It
does not mean the candidate was accepted for retention; the artifact's
statistical decision is `retained=false`.

## Raw sample summary

CPU values are child `rusage` seconds. Workload wall is the in-guest build/run
window; elapsed is the outer sample duration. Every row below has return code
0, `BUILD_OK=true`, `timed_out=false`, and cleanup status 0.

Excluded warmups:

| Sample | Arm | Workload ms | Elapsed ms | CPU s | User s | Sys s |
|---:|:---:|---:|---:|---:|---:|---:|
| warmup-a | A | 8,610 | 9,764 | 19.795957 | 15.172344 | 4.623613 |
| warmup-b | B | 8,423 | 9,208 | 22.778021 | 16.969517 | 5.808504 |

All 32 measured samples:

| Quad-position | Arm | Workload ms | Elapsed ms | CPU s | User s | Sys s |
|---|:---:|---:|---:|---:|---:|---:|
| 1-a1 | A | 8,489 | 8,990 | 19.591250 | 15.022276 | 4.568974 |
| 1-b1 | B | 8,411 | 8,907 | 22.958699 | 17.126067 | 5.832632 |
| 1-b2 | B | 8,439 | 8,937 | 22.931995 | 17.043665 | 5.888330 |
| 1-a2 | A | 8,271 | 8,775 | 20.141127 | 15.331189 | 4.809938 |
| 2-a1 | A | 8,380 | 8,882 | 20.375238 | 15.511083 | 4.864155 |
| 2-b1 | B | 8,369 | 8,854 | 22.883857 | 17.002531 | 5.881326 |
| 2-b2 | B | 8,457 | 8,969 | 22.519773 | 16.775650 | 5.744123 |
| 2-a2 | A | 8,286 | 8,807 | 20.235002 | 15.348689 | 4.886313 |
| 3-a1 | A | 8,277 | 8,771 | 20.233776 | 15.327738 | 4.906038 |
| 3-b1 | B | 8,397 | 8,914 | 22.926683 | 17.088754 | 5.837929 |
| 3-b2 | B | 8,678 | 9,169 | 23.057286 | 17.195305 | 5.861981 |
| 3-a2 | A | 8,404 | 8,906 | 20.029999 | 15.256899 | 4.773100 |
| 4-a1 | A | 8,466 | 8,988 | 19.854183 | 15.160198 | 4.693985 |
| 4-b1 | B | 8,438 | 8,937 | 23.036605 | 17.130421 | 5.906184 |
| 4-b2 | B | 8,392 | 8,901 | 22.730039 | 16.960454 | 5.769585 |
| 4-a2 | A | 8,268 | 8,778 | 20.053065 | 15.216128 | 4.836937 |
| 5-a1 | A | 8,510 | 9,007 | 19.945533 | 15.268119 | 4.677414 |
| 5-b1 | B | 8,597 | 9,105 | 22.688175 | 16.900174 | 5.788001 |
| 5-b2 | B | 8,539 | 9,055 | 22.689999 | 16.867660 | 5.822339 |
| 5-a2 | A | 8,269 | 8,783 | 20.115325 | 15.268838 | 4.846487 |
| 6-a1 | A | 8,274 | 8,778 | 20.139969 | 15.311904 | 4.828065 |
| 6-b1 | B | 8,435 | 8,938 | 22.935212 | 17.068552 | 5.866660 |
| 6-b2 | B | 8,442 | 8,960 | 23.211281 | 17.280188 | 5.931093 |
| 6-a2 | A | 8,285 | 8,765 | 20.208979 | 15.352846 | 4.856133 |
| 7-a1 | A | 8,330 | 8,833 | 20.275193 | 15.433819 | 4.841374 |
| 7-b1 | B | 8,536 | 9,050 | 22.697275 | 16.941942 | 5.755333 |
| 7-b2 | B | 8,522 | 9,016 | 22.762015 | 16.958874 | 5.803141 |
| 7-a2 | A | 8,358 | 8,849 | 20.148377 | 15.302696 | 4.845681 |
| 8-a1 | A | 8,470 | 8,962 | 20.508562 | 15.567728 | 4.940834 |
| 8-b1 | B | 8,560 | 9,078 | 22.787310 | 16.974955 | 5.812355 |
| 8-b2 | B | 8,569 | 9,077 | 22.555024 | 16.789113 | 5.765911 |
| 8-a2 | A | 8,653 | 9,148 | 19.603731 | 15.048280 | 4.555451 |

## Independent recomputation

The final artifact summary was not trusted by itself. I rebuilt every quad from
the 32 raw sample records, computed each arm's within-quad mean and the
candidate/control ratio with literal arithmetic, then reran the current
repository's deterministic `summarize_quads` analyzer. After normal JSON
serialization (tuple-to-array normalization only), the independently
recomputed statistics matched the artifact exactly.

```text
recomputed_statistics_canonical_json_match = true
```

Literal paired results:

| Metric | Control median | Candidate median | B/A median ratio | Effect | Two-sided 95% interval | B wins | A wins |
|---|---:|---:|---:|---:|---:|---:|---:|
| total child CPU s | 20.094017 | 22.806484 | 1.137399 | +13.740% | [1.124574, 1.146825] | 0 | 8 |
| child user CPU s | 15.300161 | 16.997923 | 1.112970 | +11.297% | [1.102824, 1.122284] | 0 | 8 |
| child sys CPU s | 4.802515 | 5.825305 | 1.218661 | +21.866% | [1.193188, 1.225041] | 0 | 8 |
| outer elapsed ms | 8,863.5 | 8,991.0 | 1.013906 | +1.391% | [1.004053, 1.021717] | 0 | 8 |
| workload wall ms | 8,355.5 | 8,483.75 | 1.014402 | +1.440% | [1.005370, 1.022172] | 0 | 8 |

All intervals are deterministic paired-bootstrap intervals over the eight quad
ratios. Every interval excludes 1.0 in the unfavorable direction. Wall is
therefore resolved as a regression rather than left unresolved.

Per-quad candidate/control ratios independently computed from the raw values:

| Quad | CPU | User | Sys | Elapsed | Workload wall |
|---:|---:|---:|---:|---:|---:|
| 1 | 1.154995 | 1.125728 | 1.249714 | 1.004447 | 1.005370 |
| 2 | 1.118034 | 1.094570 | 1.192297 | 1.007575 | 1.009600 |
| 3 | 1.142068 | 1.120957 | 1.208776 | 1.022968 | 1.023620 |
| 4 | 1.146825 | 1.122284 | 1.225041 | 1.004053 | 1.005737 |
| 5 | 1.132731 | 1.105802 | 1.219074 | 1.020798 | 1.021277 |
| 6 | 1.143685 | 1.120138 | 1.218248 | 1.020236 | 1.019204 |
| 7 | 1.124574 | 1.102949 | 1.193188 | 1.021717 | 1.022172 |
| 8 | 1.130385 | 1.102824 | 1.219242 | 1.002485 | 1.000350 |

The harness's candidate-favorable one-sided sign-test probability is 1.0 for
every metric because the candidate won 0/8. Independently, eight losses in
eight non-tied trials have regression-direction one-sided probability
`1/256 = 0.00390625`; the exact two-sided extreme probability is
`2/256 = 0.0078125`.

## Retention decision, confidence, and concerns

The primary CPU interval excludes 1.0 in the wrong direction, supported
secondary metrics all regress, and workload wall also excludes 1.0 in the
wrong direction. This is not a smaller-than-10% enabling win: it is a measured
13.74% total-CPU regression. The exact retention rule therefore requires a
**do-not-retain** recommendation.

Before ABBA, the Task 5 mechanism evidence supported a moderate expectation of
an end-to-end improvement, but it was explicitly non-authoritative. After this
accepted paired campaign:

- confidence that this exact candidate is an end-to-end CPU win: **below 1%**;
- confidence that the candidate regresses total CPU on this workload: **99%**;
- confidence that workload wall also regresses: **97%**;
- confidence in arm/image/overlay/source comparability: **99%**;
- confidence in the do-not-retain recommendation: **99%**.

The contradiction with Task 5 is itself useful attribution evidence. The
same-instrument writer-wait stack fell, but ABBA shows that the change displaced
or added more CPU than it removed. Task 5 also measured substantial optimistic
duplicate work and used a different traced workload for its old/new stack
screen; neither mechanism result could establish retention. Task 6 does not
claim a root cause for the 11.3% user and 21.9% sys regressions. A future
postmortem may use the retained counters/traces to separate duplicate decoding,
changed contention/concurrency, and induced Darwin kernel work, but no further
measurement is needed to decide this candidate's retention.

The exact revert dependency set is deliberately left to the controller. Per
the brief, no revert was performed here, and all target receipts plus this
report remain available for review.
