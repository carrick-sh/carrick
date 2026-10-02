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
`node-core-worker-message-port`, `spawn-loop`, `thread-spawn`, and `fork-exec`. Repeat the option for multiple selections.
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
`WARNING` line. The objective is candidate median / Docker median ≤2, using the in-guest
per-op median for creation rows and wall median otherwise. None of these observations proves a quiet host or closes signed conformance.
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

## Creation workloads

Declarations are in `scripts/perf/manifests/impact-creations.toml`; their window
prefixes and operation counts are in `impact-windows.json` beside it. The shell
loop spawns and reaps `/bin/true` 1000 times between `date +%s%N` readings. Node
creates and joins 1000 empty workers between monotonic `hrtime.bigint()` readings.
These windows include loop overhead; the shell window also includes the ending
clock-command launch and uses realtime, so a clock adjustment invalidates its
interpretation. Use the same declarations on both engines.

`fork-exec` reuses `conformance-probes/src/bin/perf_fork_exec.rs`: 20 internal
warm-ups, then 200 measured fork/exec/reap cycles. Its aggregate window is the
sum of those 200 monotonic spans. Build its native-arm64 musl executable before
selecting this workload (or using the default all-workload selection):

```sh
cd conformance-probes
CARGO_BUILD_JOBS=3 cargo build --locked --release --target aarch64-unknown-linux-musl --bin perf_fork_exec
```

The tool binds that executable into Ubuntu and includes its SHA-256 in the
workload declaration identity. A missing executable fails measurement. The
windows divide by the declared operation count; reports show median per-op
seconds for base/candidate/Docker and both Docker ratios alongside wall time.
The 2x objective uses the per-op ratio for creation rows and the wall ratio for
startup/shard rows. Missing, zero, malformed or duplicate windows fail closed.
`--operations N` overrides the shell/Node count for bounded plumbing checks;
that count participates in declaration identity and cannot mix with a different
count in a report. Carrick launches also receive the harness-derived registry
host in `CARRICK_INSECURE_REGISTRIES`, including digest-pinned local images.

## Creation plumbing validation (2026-10-02)

[Raw receipt](perf-results/2026-10-02-impact-spawn-loop/receipt.json): after
`CARGO_BUILD_JOBS=3 just build`, the signed Carrick phase ran `spawn-loop` with
`--operations 5 --samples 1`. Warm-up and measured samples exited zero, emitted
positive in-guest windows and recorded successful scoped cleanup. No Docker
workload was run; this proves measurement plumbing, not a performance ratio.
