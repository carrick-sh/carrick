# HVPatch Node child-exit / sigsuspend receipt

## Scope and red

The red source was `9167e0c7dd503b8fcd9884da774d587efd77dd03` on
macOS/arm64 HVPatch. A direct Node 24 V8 smoke invocation exited in 1.3 seconds
after printing `v8-smoke ok`; the full conformance wrapper did not exit before
the 12-second LLDB deadline. The modified-memory carrier core and event-ring
transcript were captured under
`target/conformance/node-worker-lldb/node-v8-wrapper.*` (220 MiB of cores, not
checked in).

The carrier ring proved that Node pid 8 and every Worker tid completed teardown:
the worker tids reached `registry-removed`, `vcpu-destroyed`, and `loop-return`,
then the leader reached `HVPPEXIT ... publication=complete`. The remaining
guest was GNU timeout, blocked in `WaitOnSignals` at
`vcpu_loop/mod.rs:3387`. This ruled out Worker, clear-child-tid, registry, and
vCPU retirement as the terminal blocker.

The durable reducer is
`docker/nodejs-conformance/fixtures/worker-exit-smoke.js`. It prints separate
message and Worker-exit markers. With the frozen Node image
`sha256:1ed49af83bd30401e1b275957b99a1c28f6c582ab3d987997afb5888fa302718`,
the exact shell shape was:

```text
bash -c 'timeout -s KILL 5 node worker-exit-smoke.js'
```

The Docker-only reference printed both markers and `wrapper-exit 0`. The signed
red Carrick run printed both markers, then reached the deadline and returned
`wrapper-exit 137`.

## Dynamic attribution

The existing low-perturbation
`scripts/dtrace/hvpatch-sigchld-delivery.d` capture recorded Node's
`exit_group` and its worker exits around 0.3 seconds, but no process-directed
SIGCHLD publication before the five-second timeout edge. The first publication
was at the timeout boundary. The core and source audit then established the
actual mismatch: GNU timeout had installed a caught SIGCHLD handler after
`exec`, but `HvpatchRuntimeEndpoint` retained the exact pre-exec
`KernelContext`. Its child-exit predicate therefore read the obsolete default
SIGCHLD disposition from the replaced Sighand.

The endpoint now retains a generation-safe `KernelTaskBinding` and reacquires a
coherent task signal snapshot at notification time. Task-key validation, the
current `KernelContext`/Sighand, and an exact live-thread roster are captured
together under the registry read lock, so an exec commit cannot mix old signal
authority with a new thread set. The lock is released before pending-signal
publication and wakeup. Selecting any live thread also covers the valid
retired-leader/nonleader-exec state; a reused task id is rejected by its stale
`TaskKey`.

TDD recorded both sides of the semantic boundary. The post-exec caught-handler
endpoint test was red before recapture and green after it. Separately, an
already-pending default-ignore SIGCHLD incorrectly made full-dispatch
`rt_sigsuspend` return `EINTR`; the new negative test was red first and is now
green with `WaitOnSignals`. Default-ignore and explicit `SIG_IGN` therefore
remain non-waking, while caught or terminating dispositions wake as Linux
requires.

## Candidate proof

The final source is `9f754b6ca85dd26e2ce19d1be99aed71d4ab5acf`.
`candidate-binary-identity.txt` binds the signed executable. On that exact
artifact the reducer ran three consecutive times with distinct stamped run ids;
every run printed:

```text
worker-message ok
worker-exit ok
rc=0
scoped_cleanup_count=0
```

The compact exact transcript is committed as `reducer-3x.txt`. Its unabridged
target copy is
`target/conformance/node-worker-teardown/evidence/reducer-3x-authoritative.txt`
(SHA-256
`86feea757b596b19ddd0da01dc46fbbc4ee7cf42d6d9d55b4af6a6785d4b7230`).
Runs `node-worker-receipt-d`, `-e`, and `-f` each record both markers, `rc=0`,
and `scoped_cleanup_count=0`. The fixture was exposed read-only from the
checked-in source rather than rebuilding the cached image; its SHA-256 is
`e68ea3b3ffd8610bf08508c9b72d71cb3875607146c6640b5c8da9112884f42b`.

The focused one-worker, zero-retry, cached-oracle gate selected exactly the two
affected conformance rows and launched no Docker oracle containers:

- `node-app-smoke`: MATCH, 1,944 ms / 402 ms = 4.84x.
- `node-v8-smoke`: MATCH, 749 ms / 403 ms = 1.86x.

Both ratios are below the 10x pathological-correctness threshold, but neither
measurement claims the eventual 2x performance gate. Every reducer and suite
run id had zero scoped Carrick processes after cleanup.

Fresh verification after the final safety correction:

- post-exec recapture, stale-binding, retired-leader, and sigsuspend-disposition
  tests: passed;
- `just clippy`: passed;
- `RUST_TEST_THREADS=1 just ci`: passed, including 1,323
  `carrick-runtime` unit tests and 297 runtime integration tests.

The fresh full CI transcript is preserved at
`target/conformance/node-worker-teardown/evidence/just-ci.log`: 596,322 bytes,
exit status 0, SHA-256
`0761375da29b51aaeb2df126effd3769a72d6a754259fab21b79bc03737f5e54`.
`just-ci-summary.txt` commits the command, source/binary identity, exit proof,
hash, size, target path, and the two runtime test summaries without checking in
the large log.

No broad closure or strict-probe run was performed in this cluster; those are
coordinator-owned serialized checkpoints.
