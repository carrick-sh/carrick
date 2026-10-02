# Per-landing impact receipts

`just xtask impact` compares a base and candidate signed Carrick artifact with
native arm64 Docker. The result is observational: a performance warning or an
incomplete report never changes the report command's exit status. File-write
failures still fail. Correctness acceptance remains a separate prerequisite.

Run on a quiet host, with the same machine, images, workload declarations and
environment for all three receipts. Change only the Carrick artifact between
base and candidate. Stop unrelated Carrick runs, compilers and workloads; quit
Docker Desktop for the Carrick measurements when possible. Never overlap
Carrick and Docker phases. The tool checks the opposite phase before starting
and before each sample; these checks cannot reserve the host against unrelated
commands started afterward.

```sh
CARGO_BUILD_JOBS=3 just xtask impact carrick --artifact /path/to/base/carrick --out target/impact/base.json
CARGO_BUILD_JOBS=3 just xtask impact carrick --artifact target/release/carrick --out target/impact/candidate.json
# Director-only: after all Carrick processes are gone.
CARGO_BUILD_JOBS=3 just xtask impact docker --out target/impact/docker.json
just xtask impact report --base target/impact/base.json --candidate target/impact/candidate.json --docker target/impact/docker.json --out target/impact/report.md
```

Defaults: one excluded warm-up per workload followed by exactly 10 measured
runs, no retries. `--samples N` changes the fixed count. `--workload true`
selects the `/bin/true` plumbing check; other selections are `node-startup` and
`node-core-worker-message-port`. Repeat the option for multiple selections.
Warm-up failures invalidate the measurement. Wall time includes launch and
container setup on both engines, excludes census, registry resolution and
cleanup, and ends when the launched process is reaped. The summary uses the
median (mean of the two central values for even counts) and min–max range.
CPU is the raw `RUSAGE_CHILDREN` user-plus-system delta: a host child CPU floor
for Carrick, Docker **client** CPU for Docker, not container CPU.

The worker shard is loaded from the conformance manifest plus its existing
supplement `scripts/perf/manifests/el1-real-workloads-v1.toml`. Shared
`carrick-conformance::argv` builders supply both launch envelopes, including
entrypoints, environment, filesystem flags and trap policy. The two startup
workloads use `/bin/true` in `ubuntu:24.04` and `node -e 0` using the shard image's explicit Node 24 binary entrypoint.
The Docker phase checks that the server is Linux on native arm64, refusing\nx86 engines that would emulate the ARM images. Images are resolved to\nnative-arm64 manifest digests before timing and launched
by immutable digest. Registry bytes are hash-checked and tags rechecked after
each workload. This prevents a stale cached tag from substituting other image
bytes. Docker Hub and unauthenticated registries are supported; localhost
registries use HTTP. Private registry credentials are not currently supported.

Receipts contain git HEAD for the invoking checkout, exact sample argv and run
IDs, raw timings, failures and cleanup outcomes, and the signed artifact's
SHA-256, CDHash, LC_UUID, entitlement XML and DOF presence. Use an artifact from
a known source checkout: the invoking HEAD is not a claim that an arbitrary
external artifact was built from that HEAD. Artifact identity is rechecked after
each workload. Logs are retained under `target/impact-logs/`. Carrick cleanup is
scoped through `scripts/sudo/kill.sh`; Docker cleanup removes only the sample's
named container. Docker census uses the read-only local socket API and does not
launch containers. Failure to inspect a running daemon fails closed.

A report rejects missing/failed samples, wrong phases, incompatible warm-up
policies, different commands/images, missing digests and digest mismatches.
Unreadable receipts produce an explicit `INCOMPLETE` report. No invalid row gets
a ratio. A candidate median strictly greater than 1.15 times base produces a
`WARNING` line. The objective is candidate wall median / Docker wall median
≤2. None of these observations proves a quiet host or closes signed conformance.
The existing Python EL1 A/B campaign remains the tool for paired lane experiments.

## Plumbing validation (2026-10-01)

[Raw receipt](perf-results/2026-10-01-impact-plumbing/receipt.json): signed
`just build`, then `impact carrick --artifact target/release/carrick
--workload true --samples 2 --out target/impact/plumbing.json`. One warm-up and
two measured samples exited zero and recorded successful scoped cleanup. The
artifact identity and immutable Ubuntu arm64 digest are in the receipt. This is
only plumbing evidence on the shared host, not a controlled performance claim.
No Docker workload was run. A report with a missing Docker receipt also exited
zero and explicitly reported `INCOMPLETE`; the director owns the full campaign.
