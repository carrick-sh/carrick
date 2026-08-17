# Node worker-thread teardown closure

## Goal

Make the Node app and V8 smoke fixtures exit after their successful final
assertions. Both currently print their final `ok` diagnostic and then hit the
wrapper's inner 120-second deadline. Do not increase the timeout or conflate
this with the already-fixed root-exec transaction.

## Decision reducer

Run the V8 fixture directly, without the wrapper, under a carrier-aware core
capture:

```sh
target/release/carrick debug lldb-run --deadline-seconds 12 \
  --out-dir target/conformance/node-worker-lldb --run-id node-v8-direct -- \
  --max-traps 18446744073709551615 --raw --fs host \
  --entrypoint /opt/nodejs-conformance/bin/node24 \
  localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0 \
  /opt/nodejs-conformance/fixtures/v8-smoke.js
```

- If direct Node exits, capture the full wrapper: the bug is child wait/exit
  publication around GNU `timeout`.
- If direct Node wedges, inspect the carrier core for Worker TID teardown,
  `CHILD_CLEARTID` futex wake, registry removal, vCPU destruction, and the main
  thread's wait target.

## TDD and fix

1. Add a minimal worker fixture that emits separate `message` and `exit`
   markers. Prove Docker emits both and exits, then prove Carrick red.
2. Read the always-on ring with `scripts/carrick_lldb.py`; use the existing
   FUTEXWAIT/WAKE/END and HVPTHREAD teardown phases. Prefer LLDB/core first.
3. Once one missing transition is proven, add a bounded durable
   `scripts/dtrace/hvpatch-node-worker-exit.d` only if it does not perturb the
   reducer.
4. Fix the exact thread-terminal, clear-child-tid, registry, vCPU lease, or
   parent wait invariant. Rearchitect ownership if the current ordering cannot
   make termination generation-exact.
5. Prove the reducer three times, then run both Node rows with workers=1 and no
   retries. Follow with focused tests/clippy/fmt, full `just ci`, strict probes,
   and a coordinator-owned closure checkpoint.

