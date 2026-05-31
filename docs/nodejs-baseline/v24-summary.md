# Node.js 24 Full Baseline

Status: narrow source-relative baseline collected; full upstream baseline is
not run yet.

Image digest:
`sha256:afcb9ceaa9edb682ad12aa652bfc1f91e03efc270df976a46c5d72c9bc0df4a2`.

Command used for the first narrow record:

```sh
scripts/nodejs-conformance-image.sh --image localhost:5005/carrick-nodejs-conformance@sha256:afcb9ceaa9edb682ad12aa652bfc1f91e03efc270df976a46c5d72c9bc0df4a2 --runner both --suite node-core --line 24 --filter test/parallel/test-process-argv-0.js --timeout 120 --jsonl docs/nodejs-baseline/v24-full.jsonl
```

Counts:

- Docker: `PASS` 1.
- Carrick: `TIMEOUT` 1.

The Carrick timeout left `SignalInspector` descendants until
`scripts/sudo/kill.sh nodejs-v24-core-narrow-2399` cleaned up the scoped run.
The next step is a host-bounded rerun of a small Node core shard, then the full
Node 24 baseline once timeout cleanup is deterministic.
