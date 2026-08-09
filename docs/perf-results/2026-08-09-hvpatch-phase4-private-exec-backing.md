# HvPatch Phase 4 private executable backing qualification

Date: 2026-08-09

Status: **RETAIN as a memory mechanism; Phase 4 remains RED.** This result is
not a Phase 4 closeout and is not an official CPU improvement.

## Question

Can repeated in-process `execve` operations stop eagerly materializing the
same fully patched, non-writable executable bytes without sharing one mutable
host mapping between guest processes?

The evaluated mechanism caches a bounded, unlinked, immutable file artifact of
the already-patched RX payload. Every exec obtains a fresh `MAP_PRIVATE` host
view. Guest stage 1 keeps the region non-writable, so the unsafe shared-live-
mapping design previously rejected by ABBA is not reintroduced. The exact
default-on hatch is:

```text
CARRICK_HVPATCH_EXEC_PRIVATE_FILE_CACHE=0
```

The cache holds at most 64 artifacts and 256 MiB of file extent. Cache identity
is the exact retained `Arc<Vec<u8>>` plus mapped extent; it does not use a
collision-prone payload hash. Eviction drops only the cache reference: an
active mapping retains its vnode independently.

## Provenance

- Host: macOS 27.0 build `26A5388g`, arm64.
- Worktree: `.worktrees/hvpatch`, branch `codex/hvpatch`. The qualifying binary
  was built from the worktree based on `d82be8bb`; the exact production and
  diagnostics changes measured here became `33373927` and `1ea87300` without
  intervening production edits. This document's own commit contains only the
  evidence and its fixtures.
- Signed binary SHA-256:
  `9cbf8b847de1cf12d54fc074bc557f18f827198b8b47dc8dfed52c8fa64aa730`.
- Entitlement checked live:
  `com.apple.security.hypervisor=true`.
- Backend: `--exec-backend hvpatch`.
- Image: `localhost:5005/carrick-go-conformance:1.24`, `--pull never`.
- Filesystem: `--fs host`.
- Fixture: `scripts/perf/fixtures/hvpatch-cold-go-build.sh` mounted read-only at
  `/fixture`; every cited run printed exact `ok` and `BUILD_OK` markers.
- Carrick and Docker were not run concurrently. The already-qualified Docker
  oracle count remains 68 forks / 67 execs / 69 total processes.

## Correctness and mechanism trace

The backing capture was:

```sh
target/release/carrick trace \
  --script scripts/dtrace/hvpatch-phase4-exec-backing.d \
  --trace-out target/perf/hvpatch-phase4/exec-backing-private-file.raw \
  -- run --name hvpatch-private-file-trace-20260809 --rm --raw \
  --fs host --exec-backend hvpatch --pull never \
  -v "$PWD/scripts/perf/fixtures:/fixture:ro" \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh /fixture/hvpatch-cold-go-build.sh
```

The fail-closed summary reported 1,261 complete backing events, zero bounded
events, and zero errors:

| Backing | Events | Mapped bytes | Aggregate mapping time |
|---|---:|---:|---:|
| Fresh private-file RX view | 496 | 258,064,384 | 1,580,456 ns |
| Anonymous materialization | 765 | 2,600,004,501,504 | 39,369,437 ns |

The anonymous byte total includes large sparse process apertures and therefore
must not be interpreted as resident bytes. The useful mechanism result is that
the 496 eligible executable mappings took fresh private views rather than
copying 258 MiB of repeated payload.

The exact replacement-stage trace is archived at
`target/perf/hvpatch-phase4/exec-replace-stages-private-file.raw`. It joined all
469 expected records (seven stages x 67 execs), with no join, phase, bounded,
or empty-result errors. Artifact lookup/creation cost 16,547,456 ns total; the
steady-state map-backing stage cost 48,856,713 ns total.

## Full exec latency: traced screen is negative

`scripts/dtrace/hvpatch-phase4-exec-latency.d` produced:

| Metric | Total | Per exec (67) |
|---|---:|---:|
| Full exec | 316,681,122 ns | 4.727 ms |
| Load plan | 96,818,871 ns | 1.445 ms |
| Replacement | 217,715,085 ns | 3.249 ms |
| Publication tail | 2,147,166 ns | 0.032 ms |

This is worse than the preceding lazy-page-table trace's 4.380 ms mean. A
traced run is attribution, not retention authority, but it proves this change
does not close the `<1 ms` Phase 4 exec gate.

## Untraced two-block ABBA

Two balanced eight-run blocks used the same signed binary. `on` used defaults;
`off` added:

```text
--forward-env CARRICK_HVPATCH_EXEC_PRIVATE_FILE_CACHE=0
```

The order was `on off off on on off off on`, followed by
`off on on off off on on off`. CPU is `/usr/bin/time -lp` user plus system.

| Block | Arm | CPU-s | Mean page reclaims |
|---|---|---:|---:|
| 1 | on | 3.82, 4.39, 4.32, 4.31 (mean 4.2100) | 286,324.5 |
| 1 | off | 4.35, 4.37, 4.33, 4.32 (mean 4.3425) | 301,800.0 |
| 2 | on | 4.32, 4.31, 4.35, 4.31 (mean 4.3225) | 285,251.5 |
| 2 | off | 3.85, 4.44, 4.40, 4.36 (mean 4.2625) | 301,786.0 |
| Combined | on | mean 4.2663 | 285,788.0 |
| Combined | off | mean 4.3025 | 301,793.0 |

Each block's first run was anomalously cheap regardless of arm. Removing both
first runs preserves a small 0.85% CPU direction (4.3300 on versus 4.3671 off),
which is too small to call an official speedup. The memory direction is not a
first-run artifact: every on run used 15k-19k fewer page reclaims. The combined
difference is 16,005 16-KiB pages, about 250 MiB.

Decision: retain for the repeatable memory reduction and absence of a measured
CPU regression. Describe CPU as neutral-to-modestly favorable only.

## One-VM lifecycle requalification

The retained mechanism was re-screened with the durable lifecycle scripts:

- `hvpatch-phase4-vm-lifecycle.d`: one VM create, zero workload-time destroys,
  zero errors.
- `hvpatch-phase4-process-concurrency.d`: one guest root, 68 guest forks,
  67 guest execs, 68 guest exits, peak six guest processes, one live root at
  capture end, zero errors.
- Both workloads printed `ok` and `BUILD_OK`.

Raw streams:

- `target/perf/hvpatch-phase4/vm-lifecycle-private-file.raw`
- `target/perf/hvpatch-phase4/process-concurrency-private-file.raw`

## Verification and remaining gate

Focused tests and lint at qualification time:

```sh
cargo test -p carrick-host map_private_file_is_cow --lib
cargo test -p carrick-vmm-hvf private_exec_file_artifact_reuses --lib
cargo test -p carrick-observability --lib
cargo clippy -p carrick-host -p carrick-observability \
  -p carrick-vmm-hvf --all-targets -- -D warnings
git diff --check
just build
```

The accumulated Phase 4 stack subsequently passed `just ci` on this host
(format, clippy, typed-domain lint, dependency policy, support-matrix drift,
workspace build, rustdoc, serialized host tests, and integration tests).

Phase 4 remains RED: the `<1 ms` per-exec and `<3.5 CPU-s` gates are both
missed. Signed conformance has not run for the accumulated Phase 4 stack, so
backend correctness beyond the focused workload and host gates is not yet
claimed. The next performance question is the unaccounted
replacement/load-plan time, not page-table cloning or private RX mapping.
