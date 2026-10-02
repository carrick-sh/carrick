# Stage 2a live parent capability evidence

This is a namespace correctness result within milestone 0, not milestone 0
acceptance. The exact scoped host-call/path-visit contract, signed structural
binding, lower-layer and archive matrix, and per-call comparison remain open.
Cache ownership remains in the existing dentry cache.

## Two-live-process red

`carrick-kernel-example::namespace_two_process` runs two Linux processes on
the public kernel backend. A pipe release starts independent actors; a final
handshake keeps both processes live through their namespace operations. There
is no per-operation turn-taking. The matrix covers 1/8/32/128 iterations per
actor, 0/128 unrelated directories, and shared/unrelated parents. Each actor
checks hardlink rename no-op, NOREPLACE, exchange, unlink-open, ordinary rename,
and directory rename, including physical names and file contents after exit.

On the accepted slice, a child returned errno 2 from unlinkat after a successful
exchange and open. Its parent subsequently hit the unchanged five-second pipe
bound. The ordinary example-backend error ordering reports that parent timeout
first. Temporarily inspecting the recorded child error exposed the unlink
failure; that diagnostic ordering change is not retained in the implementation.

The retained red at scale 32, population 0, unrelated parents contains:

```
Task { pid: 2, tid: 2, error: Expectation {
    label: "unlinkat", expected: "return value 0", actual: "errno 2"
} }
```

Physical evidence at
`/var/folders/8f/dl9bkkyn1zs5ycl864wv184h0000gn/T/.tmpRCBBwx`
retains `unrelated/1_15_src` with payload `b`, its alias with payload `a`, and
the exchanged other name with payload `a`. Thus the failed unlink was not a
physical disappearance or a failed exchange. Raw red/green logs are retained
under `target/el1-host-namespace/live-parent-capability/`.

## Capability lifetime correction

`get_or_open_dir_fd` formerly resolved a directory, returned its `DentryId`,
then reread the mutable directory cache for the upper descriptor. A sibling's
publication can reconcile that cache between those reads. The ID disappears
even though the physical directory and its opened descriptor remain valid.

`ResolvedDentry` now retains the upper directory descriptor while resolving
the directory under the existing cache lock. The parent adapter consumes that
capability directly. It no longer repeats the ID lookup for an already-open
upper directory. Lower-only directory materialization still uses the existing
adapter; this result does not claim that remaining path is bounded.

The changed matrix passed all 16 scale/population/parent combinations. No wait
bound, retry, namespace budget, or execution concurrency was weakened.

## Signed probe evidence and its limits

Both complete ARM64 musl and GNU fixture sets were rebuilt locally with three
build jobs and no Docker. The selected namespace/path set contains 25 probes,
including dentrycache, dirrenamecache, namei_escape, renameexchange, linkstat,
openat2resolve, openat2valid and unlinkatbindmount. The signed shards executed
all 50 libc/probe pairs with no skips, and the negative entitlement control
passed. Run ID: `stage2a-namespace-20261002-01`. Scoped cleanup reported zero
remaining processes. This first artifact predates the capability correction;
its receipt is retained as `signed-before-anchor-artifacts.jsonl`, alongside
the full transcript and SHA-256 inventory of 52 fixtures including probeinit.
It confers no signed acceptance on the changed artifact.

The durable `hvpatch-fs-op-ledger.d` omitted renameat2 and linkat from its
operation windows. Both are now included; DTrace compile-only qualification
passed. Attempts to launch the signed test executable through raw sudo DTrace
failed environment policy or traced zero selected tests. Those attempts are
not a census. Future captures must use `carrick trace` and prove live window
closure, exact artifact identity and scoped cleanup. No per-call CPU or exact
host-call improvement is claimed here.
