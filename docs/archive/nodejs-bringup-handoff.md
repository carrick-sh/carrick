# Handoff - Node.js/V8/libuv bring-up on carrick

## Latest

Harness surface checks pass. The reproducible linux/arm64 image builds Node
24, Node 26, and standalone libuv from pinned source refs, pushes to the local
registry, and has first Docker-vs-Carrick baseline records in
`docs/nodejs-baseline/`.

- Node 24 LTS full baseline target: `v24.16.0`.
- Node 26 smoke target: `v26.2.0`.
- Standalone libuv target: `v1.52.1`.
- Docker context: `docker/nodejs-conformance`.
- Shared entrypoint: `/usr/local/bin/nodejs-conformance`.
- Host wrapper: `scripts/nodejs-conformance-image.sh`.

Image:

- Tag: `localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0`.
- Digest: `sha256:afcb9ceaa9edb682ad12aa652bfc1f91e03efc270df976a46c5d72c9bc0df4a2`.

Successful build/smoke command:

```sh
scripts/nodejs-conformance-image.sh --build --push --image localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0 --runner docker --suite libuv --line 24 --filter platform_output --timeout 60
```

Result: pushed digest
`sha256:afcb9ceaa9edb682ad12aa652bfc1f91e03efc270df976a46c5d72c9bc0df4a2`
and `libuv PASS rc=0` for the Docker `platform_output` reducer.

Verification:

- `bash scripts/test-nodejs-conformance-dry-run.sh`: pass.
- `docker build --check docker/nodejs-conformance`: pass, no warnings.

## Current baseline

The durable records are:

- `docs/nodejs-baseline/v24-full.jsonl`
- `docs/nodejs-baseline/v26-smoke.jsonl`
- `docs/nodejs-baseline/libuv-full.jsonl`

Counts:

- Node 24 narrow source-relative `node-core`: Docker `PASS` 1, Carrick
  `TIMEOUT` 1. The filter is `test/parallel/test-process-argv-0.js`; this is
  not the full upstream baseline yet.
- Node 26 smoke: Docker `PASS` 3. Carrick has `v8-smoke` `TIMEOUT`,
  `npm-smoke` `TIMEOUT`, and `app-smoke` `FAIL`.
- libuv full: Docker `PASS` 1 for all 507 upstream tests in 46 seconds.
  Carrick `TIMEOUT` 1 at 120 seconds, with first signature
  `not ok 1 - platform_output`.

Useful reducers already checked:

- `node24 -e "console.log(1+1)"` passes under Carrick.
- `node26 --version` passes under Carrick.
- `node26 -e "console.log(1+1)"` fails under Carrick with V8 fatal
  `Check failed: 0 == munmap(address, size)` during environment creation.
- libuv `platform_output` under Carrick reaches
  `test/test-platform-output.c:191`, where `uv_os_get_passwd(&pwd)` returns
  `UV_ENOENT`.

Harness fixes made during baseline:

- Carrick cannot execute the shell-script image `ENTRYPOINT` as an ELF, so the
  Carrick runner overrides the entrypoint to `/bin/bash` and passes
  `/usr/local/bin/nodejs-conformance` explicitly.
- Carrick does not provide the `/dev/fd` behavior needed by process
  substitution, so suite dispatch uses a plain loop over command output.
- `npm-smoke` needs a `node` shim on `PATH` because the image exposes
  `node24` and `node26`.
- libuv refuses to run as root. The entrypoint now stages a writable copy of
  libuv's `test/` tree and uses a numeric Python `setgid`/`setuid` launcher
  instead of `setpriv`, because `setpriv` depends on guest `prctl` behavior
  that Carrick currently rejects.
- Some Carrick timeouts leave process descendants after the in-guest
  `timeout` kills its child. Cleanup must remain `CARRICK_RUN_ID` scoped via
  `scripts/sudo/kill.sh`.

Build attempt 1:

```sh
scripts/nodejs-conformance-image.sh --build --push --image localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0 --runner docker --suite app-smoke --line 24 --timeout 120
```

Result: failed in the Docker build at `make -j$(nproc)` for Node `v26.2.0`.
Node `v24.16.0` had already built and installed. The failure was V8
Turboshaft static assertions in `deps/v8/src/compiler/turboshaft/assembler.h`:
`kTaggedSize == kInt32Size` reduced to `(8 == 4)` and
`SmiValuesAre31Bits()` was false. A minimal Debian bookworm arm64 C++20
reproducer shows GCC 12 and Clang reject the same non-dependent
`static_assert` in a discarded `if constexpr` branch, while Debian trixie GCC
14 accepts it. The Dockerfile now uses `debian:trixie` and splits the Node 24
and Node 26 builds into separate layers before retrying.

Build attempt 2:

The trixie rebuild completed Node `v24.16.0`, then completed Node `v26.2.0`
through the previously failing V8 Turboshaft region, built libuv `v1.52.1`,
and exported the image. The first post-build smoke failed before executing the
suite because the host-side runner passed `/usr/local/bin/nodejs-conformance`
as an argument to an image whose `ENTRYPOINT` was already that script. The
host runner now relies on the image entrypoint and passes only conformance
options after the image reference.

## Intended workflow

```sh
scripts/nodejs-conformance-image.sh --image localhost:5005/carrick-nodejs-conformance@sha256:afcb9ceaa9edb682ad12aa652bfc1f91e03efc270df976a46c5d72c9bc0df4a2 --runner both --suite node-core --line 24 --jsonl docs/nodejs-baseline/v24-full.jsonl
scripts/nodejs-conformance-image.sh --image localhost:5005/carrick-nodejs-conformance@sha256:afcb9ceaa9edb682ad12aa652bfc1f91e03efc270df976a46c5d72c9bc0df4a2 --runner both --suite libuv --line 24 --jsonl docs/nodejs-baseline/libuv-full.jsonl
scripts/nodejs-conformance-image.sh --image localhost:5005/carrick-nodejs-conformance@sha256:afcb9ceaa9edb682ad12aa652bfc1f91e03efc270df976a46c5d72c9bc0df4a2 --runner both --suite all --line 26 --smoke --jsonl docs/nodejs-baseline/v26-smoke.jsonl
```

Next expansion should start with the current digest and a host-side timeout
around broad Carrick runs. Promote the smallest deterministic reducers first:

- V8 `munmap` invariant from `node26 -e "console.log(1+1)"`.
- libuv passwd lookup after numeric `setuid(1000)`.
- Node 24 core timeout/cleanup around `test/parallel/test-process-argv-0.js`
  and the lingering `SignalInspector` descendants.
- `app-smoke` `Error: write EPIPE` in stdio/pipe handling.

## Notes

- The v1 harness covers V8 through Node's embedded `deps/v8` and smoke fixtures; standalone `d8` is deferred.
- The image keeps source and built artifacts together so source-relative tests run against the code that produced the binary.
- Use `CARRICK_RUN_ID`-scoped cleanup for Carrick runs; do not use broad `pkill` during parallel conformance work.
