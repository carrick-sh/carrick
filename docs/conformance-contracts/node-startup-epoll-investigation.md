# Node startup epoll refusal (#1671)

The reported ARM Node startup abort is not yet reduced. The failing
`epoll_ctl` descriptor, event mask and errno remain unknown. Do not treat
the passing component tests below as evidence that Node starts, or infer an
errno from libuv's assertion.

The applicable contract is `kernel.el1.epoll-zone`. Its shared host entry
is `NetView::epoll_ctl` in `dispatch/net/epoll_ops.rs`. Eventfds and pipe
ends belonging to the epoll's IPC authority are registered in its zone
record; other descriptions use its host interest map. A reduction must
exercise this production entry, including descriptor creation, rather
than call the registration helper directly. In-zone registrations must
not acquire a host readiness pipe as their readiness authority.

## Linux worker investigation

The existing kernel epoll unit selection completed with 77 passed and no
failures:

```sh
cargo test -p carrick-kernel --lib epoll -- --skip serial_host
```

This runner has no Docker, bpftrace or macOS/DTrace, and no passwordless
sudo. The requested ARM oracle census and Carrick trace were unavailable.
The director's `carrick-evidence/eco-check-2026-11-05/node3-*` evidence was
not present here.

An additional diagnostic used the official Linux x86_64 Node 24.16.0
distribution. It prints its version natively. A local OCI archive bundled
that executable, the host's dynamic libraries and `/bin/sh`; no Docker
daemon or remote image was involved. The Linux CLI built successfully,
but its root `/node -e 'console.log(process.version)'` run exited 125
before guest startup with:

```text
carrick: trap engine failed: hypervisor operation failed: production initial MM refused: status 2
```

That is a KVM bring-up blocker, not a reproduction of the epoll refusal.
It does not establish which descriptor or flags the director's image uses.
A native GDB syscall catchpoint also produced no `epoll_ctl` events for
the version-print and timer examples, so it supplies no startup census.
No production behavior was changed on this evidence.

## Required continuation

Obtain the oracle startup registration sequence and the Mac refusal from
the original image, identifying the target descriptor's creation and any
duplication or close before registration. Preserve the numeric errno and
event mask. Then add the corresponding production-entry witness, prove it
red on main, and correct the shared path. Retain the zone's waiter and
readiness ownership. The director still owns the exact-image Mac Node
rerun and signed acceptance; neither is discharged by these unit tests.
