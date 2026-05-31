# Node.js/V8/libuv Baseline Triage

Status: harness implemented; baseline not run.

## Method

- Build `docker/nodejs-conformance` for `linux/arm64`.
- Run Docker and Carrick through the same `/usr/local/bin/nodejs-conformance` entrypoint.
- Use JSONL records as the durable source of truth.
- Treat Docker failures as oracle/environment cancels until rechecked.
- Treat Carrick-only failures as bring-up gaps and reduce them before runtime fixes.

## Initial commands

```sh
scripts/nodejs-conformance-image.sh --build --push --runner both --suite node-core --line 24 --jsonl docs/nodejs-baseline/v24-full.jsonl
scripts/nodejs-conformance-image.sh --runner both --suite libuv --line 24 --jsonl docs/nodejs-baseline/libuv-full.jsonl
scripts/nodejs-conformance-image.sh --runner both --suite all --line 26 --smoke --jsonl docs/nodejs-baseline/v26-smoke.jsonl
```

## First cluster buckets

- V8 memory/JIT/WebAssembly.
- libuv event loop, epoll, eventfd, timerfd, inotify, pipes, and sockets.
- `child_process`, `worker_threads`, signals, and process lifecycle.
- Filesystem, temp dirs, symlinks, and non-UTF8 paths.
- DNS, TCP loopback, stdio, TTY, and process title.
- npm cache, package script execution, and subprocess behavior.
