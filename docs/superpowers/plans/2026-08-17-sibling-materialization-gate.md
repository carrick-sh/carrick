# HVPatch sibling materialization gate closure

## Goal

Remove the `go-os_exec` sibling-materialization start-gate deadlock without
raising its deadline, and recover every assertion hidden after the abort.

## Proven failure

`go-os_exec` aborts after 30 passes and one skip while Docker reaches 86 passes
and two skips. Stderr records three simultaneous materialization-gate failures
with `process_exiting=false` and `clone_cancelled=false`. The gate and its
fail-closed deadline live in `crates/carrick-vmm-hvf/src/vcpu_loop/threads.rs`;
the waiting owner and wakeup loss are not yet proven.

## Execution

1. Preserve the suite-level red result:

   ```sh
   just conformance full --lane hvf --suite go-os_exec \
     --workers 1 --flake-retries 0 \
     --jsonl target/conformance/go-os-exec-red.jsonl
   ```

2. Test this candidate reducer and adopt it only if it reproduces the same gate
   failure:

   ```sh
   CARRICK_RUN_ID=os-exec-concurrent-red timeout 60s \
     target/release/carrick run --raw --fs host \
     -w /usr/local/go/src/os/exec \
     localhost:5005/carrick-go-conformance:1.24 \
     /conformance/os_exec.test -test.v \
     -test.run '^TestConcurrentExec$' -test.short
   ```

3. At the ten-second gate, use `carrick debug lldb-run` to save a
   modified-memory carrier core and `bt all`; inspect the event ring, logical
   guest-thread census, vCPU leases, topology lock, and fork-quiesce state. Do
   not increase the deadline. Use `scripts/dtrace/hvpatch-mn-scheduler.d` only
   after confirming it does not perturb reproduction.

4. In a separate Docker-only phase, capture the exact clone/vfork/exec/wait
   sequence with in-container `bpftrace`. Add a red unit test for the proven
   admission/publication/wakeup invariant before changing the runtime.

5. Fix or rearchitect the start-gate ownership protocol so publication and
   wakeup are generation-exact across vCPU reclaim and cancellation. Prove the
   reducer green three consecutive times, then rerun `go-os_exec`.

6. Run musl and GNU `vforkexecthread` as adjacent regression guards without
   claiming they share this mechanism, followed by `RUST_TEST_THREADS=1 just
   ci`, the complete closure probes, and the full cached-oracle checkpoint.
   Commit diagnosis/reducer, runtime fix, and ledger refresh separately.
