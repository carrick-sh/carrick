# Go net/http epoll ready-queue closure

## Goal

Replace the blocked `go-net_http` path with Linux-ready-list semantics and make
the full suite complete with exact assertion parity. A longer timeout or
Darwin-kqueue readability workaround is not completion.

## Proven failure

`go-net_http` blocks for 540.442 seconds versus Docker's 4.305 seconds and
hides 1,388 assertion comparisons. The last started test is
`TestOmitHTTP2Vet`. Prior postmortem evidence recorded repeated
`EPEDGE -> EPMASK -> EPWAIT ready=0`; that evidence must be revalidated on the
current binary before changing code. Likely owners are
`crates/carrick-runtime/src/dispatch/fd_table.rs` and the epoll
drain/recompute/latch paths in `crates/carrick-runtime/src/dispatch/net.rs`.

## Execution

1. Prove the focused current reducer red three times:

   ```sh
   CARRICK_RUN_ID=net-http-omit-red timeout 90s \
     target/release/carrick run --raw --fs host \
     -w /usr/local/go/src/net/http \
     localhost:5005/carrick-go-conformance:1.24 \
     /conformance/net_http.test -test.v \
     -test.run '^TestOmitHTTP2Vet$' -test.short
   ```

2. Use `carrick debug lldb-run` with the same argv and save a modified-memory
   carrier core at the blocked point; the older investigation found tracing
   perturbative. Confirm the current event ring repeats the edge/mask/wait
   topology before reusing the prior diagnosis.

3. In a Docker-only phase, use in-container `bpftrace` to record `epoll_ctl`
   and `epoll_wait` enter/exit behavior for the exact test. Do not use guest
   `strace`.

4. Add a deterministic red host/unit reducer for the discovered ready-list
   invariant. Implement a typed Carrick-owned deliverable-ready queue if the
   evidence confirms raw source-kqueue readiness cannot implement Linux epoll
   latching without spinning or losing an edge.

5. Run the reducer three times, then the originating suite:

   ```sh
   just conformance full --lane hvf --suite go-net_http \
     --workers 1 --flake-retries 0 \
     --jsonl target/conformance/go-net-http-green.jsonl
   ```

6. Run the epoll probe family, `RUST_TEST_THREADS=1 just ci`, the complete
   closure probes, and the full cached-oracle closure checkpoint. Commit the
   durable core/trace diagnosis, reducer, runtime change, and ledger update at
   separate reviewable boundaries.

