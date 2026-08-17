# Post Node root-exec transaction closure checkpoint

This checkpoint measures the reviewed root-exec stage-2 transaction fix across
the complete frozen macOS/HVF arm64 conformance surface. Carrick ran first;
Docker ran afterward only for 84 non-cacheable oracle rows. The strict probe
gate then ran both arm64 libc sets on the same signed Carrick binary.

## Artifact

- Binary source: `52554a8d9376539464922641e7098029c88459f8`
- Probe-build tooling source: `ce1ec732fc97134bf78087fd22ca83b300688a25`
- Ledger/controller tooling source: `b21b55d504f6caa781e6d2570c9a8a822b0bb4a8`
- Signed Carrick SHA-256: `dca649d43b6d839dbd27b3b043bd651fc12a20640559bf2c224733890c5fb1cb`
- CDHash: `37cbc540824e0a078e8ff529ba696b8b51f73d9e`
- LC_UUID: `6A516A5A-27F2-3EF7-92C3-5F12046A6C8A`
- Hypervisor entitlement: present/true
- `__dof_carrick`: present

## Complete results

- Suites: 2,127 unique rows; 1,198 MATCH and 929 INCOMPLETE.
- Blocked timeouts: 6, down from 10.
- Semantic assertion gaps: 7,006, down from 8,317.
- Unexercised assertion rows: 10,037, down from 11,278.
- Infrastructure-affected suites: 605, down from 609.
- Strict probes: 858/858 rows; 844 PASS and 14 FAIL, improved from 842/16.
- Valid completing `>=10x` pathologies: 7.

The largest demonstrated fan-out is liveness: `go-net_http` now completes
1,316 assertions, CPython asyncio completes 64, and LTP `kill10`, `shmctl05`,
and `waitpid11` became MATCH. The musl `vforkexecthread` probe also became PASS.

The fix does not close Node. App and V8 reach their final JavaScript success
marker and then hit the wrapper's inner 120-second deadline. Libuv reaches
assertion 332 of a declared 507-test plan before accumulated child-process
timeouts hit the inner 180-second deadline. These are assigned to the next
worker-thread teardown and libuv child-lifecycle plans.

Two unrelated suite rows changed from MATCH to INCOMPLETE (`go-runtime_pprof`
and `ltp-exit_group01`) and remain explicit backlog; no baseline waiver was
added.

## Raw evidence

- Results JSONL SHA-256: `28216111dd5ccfaa806d07006cc75bce8bce9e9523759652ab72a17ceb1a8860`
- Suite log SHA-256: `ae75d5e9a5a1a37192180fdaa4935baa79504312aa26a4876e7d5a4227e57144`
- Probe log SHA-256: `059dc4950842f79f5fb242b7d85ec59af36fa0ff48497cc216bc06435deacd62`
- Runtime paths: `target/conformance/closure-after-node-exec/`
- Cleanup: zero scoped Carrick processes and zero `conf-*` containers.

The closure-only build is serialized and completed both 430-binary sets. The
recorded probe log contains the successful complete build and run.
