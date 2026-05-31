# Handoff - Node.js/V8/libuv bring-up on carrick

## Latest

Harness surface checks pass. The reproducible linux/arm64 image now builds
Node 24, Node 26, and standalone libuv from pinned source refs, pushes to the
local registry, and passes the Docker app smoke.

- Node 24 LTS full baseline target: `v24.16.0`.
- Node 26 smoke target: `v26.2.0`.
- Standalone libuv target: `v1.52.1`.
- Docker context: `docker/nodejs-conformance`.
- Shared entrypoint: `/usr/local/bin/nodejs-conformance`.
- Host wrapper: `scripts/nodejs-conformance-image.sh`.

Image:

- Tag: `localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0`.
- Digest: `sha256:64fb5b40446f890f0ac99d272d5238e6ced29dfe597d18ac7f783c0fcd1d6743`.

Successful build/smoke command:

```sh
scripts/nodejs-conformance-image.sh --build --push --image localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0 --runner docker --suite app-smoke --line 24 --timeout 120
```

Result: pushed digest
`sha256:64fb5b40446f890f0ac99d272d5238e6ced29dfe597d18ac7f783c0fcd1d6743`
and `app-smoke PASS rc=0`.

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
scripts/nodejs-conformance-image.sh --build --push --runner both --suite node-core --line 24 --jsonl docs/nodejs-baseline/v24-full.jsonl
scripts/nodejs-conformance-image.sh --runner both --suite libuv --line 24 --jsonl docs/nodejs-baseline/libuv-full.jsonl
scripts/nodejs-conformance-image.sh --runner both --suite all --line 26 --smoke --jsonl docs/nodejs-baseline/v26-smoke.jsonl
```

The first real baseline should update this handoff with:

- exact image digest,
- Docker-vs-Carrick counts,
- top Carrick-only clusters,
- first reducer/probe candidates,
- and any harness limitations discovered during the run.

## Notes

- The v1 harness covers V8 through Node's embedded `deps/v8` and smoke fixtures; standalone `d8` is deferred.
- The image keeps source and built artifacts together so source-relative tests run against the code that produced the binary.
- Use `CARRICK_RUN_ID`-scoped cleanup for Carrick runs; do not use broad `pkill` during parallel conformance work.
