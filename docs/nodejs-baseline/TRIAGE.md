# Node.js/V8/libuv Baseline Triage

Status: first Docker-vs-Carrick baseline collected against image digest
`sha256:afcb9ceaa9edb682ad12aa652bfc1f91e03efc270df976a46c5d72c9bc0df4a2`.

## Method

- Build `docker/nodejs-conformance` for `linux/arm64`.
- Run Docker and Carrick through the same `/usr/local/bin/nodejs-conformance` entrypoint.
- Use JSONL records as the durable source of truth.
- Treat Docker failures as oracle/environment cancels until rechecked.
- Treat Carrick-only failures as bring-up gaps and reduce them before runtime fixes.

## Initial commands

```sh
scripts/nodejs-conformance-image.sh --image localhost:5005/carrick-nodejs-conformance@sha256:afcb9ceaa9edb682ad12aa652bfc1f91e03efc270df976a46c5d72c9bc0df4a2 --runner both --suite node-core --line 24 --filter test/parallel/test-process-argv-0.js --jsonl docs/nodejs-baseline/v24-full.jsonl
scripts/nodejs-conformance-image.sh --image localhost:5005/carrick-nodejs-conformance@sha256:afcb9ceaa9edb682ad12aa652bfc1f91e03efc270df976a46c5d72c9bc0df4a2 --runner both --suite libuv --line 24 --jsonl docs/nodejs-baseline/libuv-full.jsonl
scripts/nodejs-conformance-image.sh --image localhost:5005/carrick-nodejs-conformance@sha256:afcb9ceaa9edb682ad12aa652bfc1f91e03efc270df976a46c5d72c9bc0df4a2 --runner both --suite all --line 26 --smoke --jsonl docs/nodejs-baseline/v26-smoke.jsonl
```

## Current counts

- `v24-full.jsonl`: Docker `PASS` 1, Carrick `TIMEOUT` 1 for the narrow
  `node-core` filter `test/parallel/test-process-argv-0.js`.
- `v26-smoke.jsonl`: Docker `PASS` 3; Carrick `TIMEOUT` 2 and `FAIL` 1.
- `libuv-full.jsonl`: Docker `PASS` 1 for all 507 libuv tests; Carrick
  `TIMEOUT` 1 after `not ok 1 - platform_output`.

## First cluster buckets

- V8 memory mapping: Node 26 starts with `--version`, but
  `node26 -e "console.log(1+1)"` fails under Carrick with
  `Check failed: 0 == munmap(address, size)` during V8 environment creation.
  Docker passes the same v26 smoke fixtures. Next reducer target:
  a checked-in probe for mmap/munmap alignment and partial unmap behavior used
  by V8's allocator.
- libuv user identity/platform output: Docker passes all 507 upstream libuv
  tests. Carrick times out after `platform_output`; the filtered reducer hits
  `test/test-platform-output.c:191`, where `uv_os_get_passwd(&pwd)` returns
  `UV_ENOENT` after numeric `setuid(1000)`. Next reducer target: getuid,
  setuid, getpwuid, and passwd/group lookup coherence after UID changes.
- Node 24 core process lifecycle: Docker passes
  `test/parallel/test-process-argv-0.js`; Carrick times out and leaves
  `SignalInspector` descendants until `CARRICK_RUN_ID` scoped cleanup. Next
  reducer target: process wait/signal cleanup around a minimal Node child.
- Stdio/pipe behavior: Node 26 `app-smoke` passes under Docker and fails under
  Carrick with `Error: write EPIPE`. Next reducer target: a focused stdio
  write/pipe-close case before promoting to `conformance-probes`.
- Harness limitation: broad Carrick suites need an outer host timeout in
  addition to the in-guest suite timeout, because killed children can leave
  Carrick process trees alive long enough to block JSONL append.
