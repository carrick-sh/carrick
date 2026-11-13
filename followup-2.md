# followup-2: node:22-slim's entrypoint fork hits #2226; link it there

Found in the work on #2235, step 1 (main `ace226052`, real KVM).

#2226 reproduces the idle-peer `FaultDoorbellWord(14)` with a Python thread. The node
scoreboard rows hit the same signature through a **fork**, not a thread. The node image's
`docker-entrypoint.sh` runs `$(command -v "$1")`, and that subshell child runs on the
idle peer (CPU 1) and page-faults there. The idle lane has no fault-doorbell arm, at
`crates/carrick-runtime/src/vcpu_loop/executor/cpl0.rs:1371`.

Minimal reproducer:

```
carrick run --rm --entrypoint /bin/sh node:22-slim -c 'x=$(echo sub); echo got-$x'
```

It exits 125. The loaded lane then reports a CR3/root mismatch: expected `0x4856000`,
actual `0x4862000`.

**Proposal:** add this fork reproducer to #2226 as a second witness shape, and treat #2226
as the first blocker of node-version and node-child on x86.
