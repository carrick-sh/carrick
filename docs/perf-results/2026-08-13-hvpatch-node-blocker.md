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

## Narrowed by experiment

Three follow-ups, all on the signed binary and the same image:

| invocation | result |
| --- | --- |
| `node --version` | **works** — prints `v22.23.2` |
| `node --max-old-space-size=64 -e ...` | same abort |
| `node --no-node-snapshot -e ...` | same abort |

This is decisive about where the fault is NOT. The binary loads, relocates and
executes host-native code correctly — `--version` runs to completion — so this
is not ELF loading, not the dynamic linker, and not general execution. And the
abort is **independent of heap size** and survives disabling Node's own
startup snapshot, so it is not a budget being exceeded and not Node's snapshot
format: it is the FIRST `MemoryChunk` allocation failing.

That signature points at V8's large aligned virtual reservation. With pointer
compression, V8 reserves a multi-GiB region with a hard ALIGNMENT requirement
(the cage), maps it `PROT_NONE`, and then commits sub-ranges inside it. The
question to answer next is therefore narrow and testable in isolation, without
Node in the picture:

1. Can a guest reserve a multi-GiB `PROT_NONE` region under HVPatch at all?
2. Is the returned address aligned as requested when the guest asks for
   alignment by over-reserving and trimming — i.e. does `munmap` of a
   sub-range of a live reservation behave?
3. Can it then commit a sub-range with `mmap(MAP_FIXED)` over the reservation?

Each is a probe-sized question, and the `--fs`-independent answer belongs in a
conformance probe rather than in a Node run. Note carrick's 32 GiB arena and
the `CARRICK_DSR_ZERO_REMAP` anon-reuse path are both in this area.

### Answered, and the hypothesis is REFUTED

`conformance-probes/src/bin/mmapcage.rs` asks exactly those three questions:
over-reserve `PROT_NONE`, `munmap` the head and the tail to trim to alignment,
then commit a window with `MAP_FIXED` and check it reads zero and is writable.

**carrick MATCHES the Docker oracle on all six assertions, at 256 MiB
alignment AND at V8's real 4 GiB alignment (an 8 GiB over-reservation).**

So the aligned-cage reservation is not the bug. Whatever breaks Node is
downstream of it, and the remaining candidates are narrower: the number or
rate of separate `MemoryChunk` mappings rather than their size or alignment,
the `MAP_NORESERVE`-less variants V8 also uses, permission changes on an
already-committed sub-range, or a limit (`RLIMIT_AS`, a VMA count cap) that a
single large reservation does not reach. The probe stays as the record that
this ground is covered, so the next investigation starts past it.

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
