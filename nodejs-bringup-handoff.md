# Handoff - Node.js/V8/libuv bring-up on carrick

## Latest

Harness surface checks pass. The first full image build attempt reached the
Node 26 source build and failed before producing an image.

- Node 24 LTS full baseline target: `v24.16.0`.
- Node 26 smoke target: `v26.2.0`.
- Standalone libuv target: `v1.52.1`.
- Docker context: `docker/nodejs-conformance`.
- Shared entrypoint: `/usr/local/bin/nodejs-conformance`.
- Host wrapper: `scripts/nodejs-conformance-image.sh`.

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
