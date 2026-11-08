# Production CPL0 thread birth (#1892)

The unchanged `kernel.el1.thread-lifecycle` production-entry binding
`cpl0_entry::production_clone_thread_runs_and_exits_without_ending_parent`
now runs a real guest thread through the production image and executor pool.
It was red on the round-one head: clone returned counted ENOSYS (38), rather
than reaching the parent's status 7. The fixture, guest bytecode and existing
assertions are unchanged.

## Ownership and publication

The common Linux lifecycle owner still decides clone flags, credentials,
NPROC limits, TID outputs, birth rollback, raw nonfinal exit and clear-tid.
`El1PendingFamilies` can now use its typed native scheduler source without an
ARM `Zone`. The x86 frame adapter captures the actual SYSCALL/XSAVE state and
changes only the child's return register, user stack and FS TLS base.

Fresh CPL0 root admission receives bounded empty control storage retained by
the carrier until all guest CPUs and graph/control references have gone.
There are no issued sibling identities or preloaded sibling contexts in that
storage. `NativeThreadStock` issues identities on demand, checks resource
limits, returns rollback claims, and waits on its existing release notification
when an in-flight birth or final retired-control pin prevents reuse. The same
stock owner already serves native fork children. Host-served ARM roots retain
their existing external stock owner.

A native Born member must enter the exact-record registry before runnable
publication: a different CPU may select it immediately. Registration reuses
the common member-admission transaction and its retained pending/signal
custody. A Born member already admitted before terminal close may finish
registration while the process topology is reserved. The x86 resume loop uses
the common registered-member entry, including each sibling's exact control,
rather than the leader-only entry. Retirement gives the production pool its
typed handoff receipt; no host thread implements guest clone or raw exit.

## Join and futex custody

The witness uses glibc thread flags plus CHILD_SETTID. Parent and child TID
outputs share one word; PARENT_SETTID orders its publication before the parent
returns. A bounded futex handshake prevents the child from exiting before the
parent runs. The child records gettid and invokes raw exit. The parent requires
clear-tid completion, the child's expected gettid, and its own unchanged gettid
before exit_group(7). Both waits retain the existing five-second deadlines;
no retries, polling, timeout increase or host clone/futex fallback was added.

The native futex adapter lives in the common Linux owner and uses the shared
Linux `serve_futex` policy. It compares an acquire atomic word under the
existing scheduler bucket, saves the exact native context, enrolls once,
probes signal interruption, and releases execution with a typed receipt.
Owner-refused input preserves its relative deadline through the existing
native service continuation. Shared operations are admitted here only when
the MM owner authenticates private anonymous storage. Shared file and shared
anonymous mappings still need their separate object-key authority and remain
unrouted by this adapter.

Linux distinguishes PRIVATE keys from shared operations on private anonymous
storage even within one MM; see the clean-room
[gVisor futex key contract](https://pkg.go.dev/gvisor.dev/gvisor/pkg/sentry/kernel/futex#KeyKind)
and [futex(2)](https://man7.org/linux/man-pages/man2/futex.2.html).
The native queue key tags an otherwise unused alignment bit for the latter;
clear-tid wakes that same shared key. Private wake does not match it. The
original aligned address alone is used for guest memory access.

`production_native_futex_timeout_returns_etimedout` additionally parks a sole
native thread, then requires errno 110 and zero futex refusals. It was red
with the previous x86 timer's signal-wait EAGAIN result (guest status 9), while
the identical ELF exited 7 on native x86 Linux. Bucket futex expiry now uses
the common Linux ETIMEDOUT result; object/signal waits retain their own
continuation completions. This asserts a result, not elapsed-time performance.

The VM-free fresh-root stock bindings cover claim rollback without new
identities, NPROC refusal, exhausted in-flight stock parking, notification on
claim release, retry of the exact returned identity, and terminal withdrawal
of reserved stock. Existing ARM native stock tests cover retired-control
pins and repeated reuse. One production birth/retirement requires zero host
clone/exit implementations and zero counted clone refusals. Existing lifecycle
scaling budgets are unchanged; a single birth supplies no scaling or runtime
ratio acceptance.

## Remaining work

The x86 exit_group and exec witnesses cancelling a parked anonymous operation
still depend on #1863's ARM witness and implementation, absent on this main
base. This PR remains **Part of #1892**. No such terminal-cancellation witness,
full two-thread production-binding audit, signed HVF result, or lifecycle
runtime-ratio acceptance is claimed. Signed evidence remains with the director
and merge-group lane. Worker gate evidence is recorded on draft PR #1902.
