# Node.js is BLOCKED on HVPatch, not merely slow

**Recorded 2026-08-13.** hybrid.md requires CPython, Node.js and Rust
workloads within 2x Docker on the shipped backend. Measuring Node first
produced a functional failure rather than a ratio, which is the more important
result and is recorded here so the criterion is not mistaken for a perf gap.

## What happens

`node:22-slim` (native arm64), signed binary, `--exec-backend hvpatch`:

```text
# Fatal JavaScript out of memory: MemoryChunk allocation failed during
# deserialization.
----- Native stack trace -----
 ... node::Start(int, char**) [node]
```

Every run aborts. The same image and command under native arm64 Docker
completes in 0.29 s wall, three runs of three.

| | result | wall | host CPU |
| --- | --- | ---: | ---: |
| Docker (native arm64) | OK, 3/3 | 0.29 s | 0.01 s\* |
| carrick hvpatch | **abort, 0/3** | 0.37 s | 0.27 s |

\* Docker's host CPU is near zero because the work runs inside the LinuxKit
VM; only wall time and guest-perceived CPU are comparable across the two, as
[`2026-08-13-hvpatch-guest-vs-host-cost.md`](2026-08-13-hvpatch-guest-vs-host-cost.md)
established. No ratio is quoted here because the workload does not complete.

## Reading the failure

The abort is in V8's **startup-snapshot deserialization**, before any user
JavaScript runs — `-e` never executes, so this is not about the workload.
"MemoryChunk allocation failed" is V8 failing to obtain a heap chunk with the
alignment it requires: V8 reserves a region and trims it to an aligned
sub-range, which depends on `mmap` honouring hint, alignment and
reserve/commit semantics precisely.

That makes the first suspects carrick's `mmap` lowering — hint handling,
`PROT_NONE` reserve followed by commit, and unmap-of-a-sub-range — rather than
anything Node-specific. Note the project's own dual-port oracle guidance
applies directly: Go's `mem_darwin.go` shows the idiomatic Darwin spelling of
reserve/commit (`mmap(PROT_NONE, MAP_FIXED)` to reserve, `MADV_FREE_REUSABLE`
/`REUSE` to decommit/recommit) and carrick's job is to translate the guest's
INTENT, not re-issue the Linux mechanism.

## Status of the workload criterion

- **Node.js — blocked.** Must run before it can be timed.
- **CPython — not yet measured.** No CPython image is currently in the local
  registry (`localhost:5005/_catalog` lists only `carrick-go-conformance` and
  `carrick-nodejs-conformance`); `localhost:5005/cpython-test:3.12.13` exists
  as a local Docker image but is not served by the registry carrick pulls from.
- **Rust — not yet measured.**

Also worth recording so the next attempt does not repeat it: the in-tree
`carrick-nodejs-conformance` image is a conformance HARNESS (its entrypoint is
`nodejs-conformance`, and it ships `/opt/node-src` and `/opt/libuv-src`
sources) — it has no `node` on `PATH`, so a plain `node -e` invocation fails
with `unknown option: node`. Use a stock `node:` image for timing work.
