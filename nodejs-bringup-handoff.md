# Handoff - Node.js/V8/libuv bring-up on carrick

## Latest

The reproducible harness is being introduced before any Node baseline is run.

- Node 24 LTS full baseline target: `v24.16.0`.
- Node 26 smoke target: `v26.2.0`.
- Standalone libuv target: `v1.52.1`.
- Docker context: `docker/nodejs-conformance`.
- Shared entrypoint: `/usr/local/bin/nodejs-conformance`.
- Host wrapper: `scripts/nodejs-conformance-image.sh`.

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
