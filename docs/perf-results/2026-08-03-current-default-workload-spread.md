# Current-default workload spread

**Date:** 2026-08-03
**Scope:** shipped-default Darwin/AArch64 native DSR, persistent store default
on
**Decision:** refresh the multi-shape scoreboard; do not replace the official
five-sample cold-build ratio

## Authority

The run used the clean pre-design source and its already signed release binary:

- source commit: `e87523a8e43fb7cac2daf7a1c8465cbdac4b0998`;
- executable SHA-256:
  `a6bb3969ec593bfb0e0271087fc9edbac4943dd2cce33a984536df5b35ae9d49`;
- Mach-O UUID: `6A228EC6-3600-3101-BC35-8A04968BA4FC`;
- ad-hoc signature verified and `__TEXT,__dof_carrick` present;
- image:
  `localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`
  (`arm64`);
- `CARRICK_DSR_PERSISTENT_STORE` and `CARRICK_DSR_STORE_DIR` unset;
- default ABI-8 store authority inode `350219674`, 2,676 payload files and
  669,816 KiB before and after the run; and
- run window `2026-08-03T22:45:41Z` through `22:47:15Z`.

An earlier preflight found `mediaanalysisd` consuming one full core. Timing was
deferred until six five-second observations showed it at 0.0% and no Carrick or
Docker workload was active. Docker Desktop and its local registry remained
available for the later oracle phase. Power was AC and macOS reported no
thermal, performance, or CPU-power warning; power source is metadata, not an
acceptance gate.

`scripts/perf/workload-spread.sh 3` ran every Carrick sample first and every
Docker sample second. No two engines overlapped. Each number is in-guest wall,
excluding container lifecycle.

The preflight attempted a `dwarfdump --uuid` spelling unsupported by this
host's tool and recorded that error without stopping. The UUID above was
subsequently read with `otool` and stored separately; the executable digest,
signature, source, image, and workload run were unaffected.

## Results

| workload | Carrick samples (ms) | Docker samples (ms) | medians (ms) | ratio |
|---|---|---|---:|---:|
| startup | 28, 31, 32 | 0, 0, 0 | 31 / <1 | not resolved |
| compute (`awk` 8M) | 370, 350, 359 | 112, 102, 106 | 359 / 106 | **3.3868x** |
| fs-walk | 278, 254, 265 | 19, 14, 14 | 265 / 14 | **18.9286x** |
| exec-20 (`compile -V`) | 1,396, 1,366, 1,371 | 19, 18, 19 | 1,371 / 19 | **72.1579x** |
| build-cold | 8,690, 8,926, 8,671 | 828, 799, 792 | 8,690 / 799 | **10.8761x** |
| second cold-equivalent row | 8,596, 8,588, 8,652 | 798, 811, 794 | 8,596 / 798 | **10.7719x** |

The script prints `31.0x` for startup because it divides by
`max(docker_ms, 1)`. Docker's millisecond-rounded median is zero, so that
ratio is a display floor, not a measurement, and is deliberately not quoted.

The row named `build-warm` by the script remains cold-equivalent: every sample
starts a fresh container and cannot inherit the primed `GOCACHE`. It is shown
under an honest label above.

## Interpretation

The cold-build refresh is 4.13% slower in ratio than the authoritative
five-sample result (10.8761x versus 10.4446x). This three-sample spread has no
RUSAGE CPU floor or counterbalancing, so it confirms the current performance
band but does not supersede the official 8,575 / 821 ms scoreboard.

The spread changes the ranking in two useful ways:

- compute is already near the 3x target, but its 253 ms absolute excess is
  only about 3.2% of this spread's cold-build gap;
- fs-walk remains a high ratio, but its 251 ms absolute excess is likewise
  only about 3.2% of the cold-build gap; and
- the 20-exec shape is the largest operation amplification at 72.16x and
  1,352 ms of absolute excess for 20 executions. It is not directly scalable
  to the parallel build without a current exec census, so no build speedup is
  projected from it.

The current-default CPU/module/shape captures independently put JIT execution
at 46.505% of total CPU and the common trusted-entry sequence at a projected
12.2% of total CPU. That is the only freshly measured bucket currently above
the campaign's 10% opportunity threshold. The next measurement therefore
separates guard-fallthrough, direct-link, and indirect-cache arrivals as
specified in
[`2026-08-03-trusted-entry-route-attribution-design.md`](../superpowers/specs/2026-08-03-trusted-entry-route-attribution-design.md).

## Raw artifacts

Target-only artifacts remain under
`target/perf/current-default-scoreboard/`:

- `workload-spread-n3.log`:
  `c0f233ee1e5337beeb032798f0aba7ac9145491229c144d24e5dfca150773d91`;
- `preflight.txt`:
  `b07bb48aed75fd78aa290dfbd1016a1b367733ff2be3b3b751965402bcfb9288`;
- `postflight.txt`:
  `a84b9128a24e0735984fcdd2c1828ccdb8ce1d99d8a988ed910b89bc0bcdfd09`;
  and
- `uuid.txt`:
  `93bfd4f5e105204cfc59233ae11e1866ef669fae317adf77b7f4dc1f36851016`.
