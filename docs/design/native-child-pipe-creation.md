# Native child pipe creation (#1346)

Status: investigation only. The native-child `pipe2` route is still missing.
This note does not claim the issue's implementation or runtime acceptance.

The VM-free production-dispatch witnesses in
`carrick-el1-linux::aarch64_process_tests` reproduce the failure:
`serial_host_native_child_pipe_libc_zero_flags` and
`serial_host_native_child_pipe2_nonblock_cloexec` both return `Forward`
instead of `Served` with result zero. Each fixture forks a native child while
the parent remains live. Its positive tail forks again from the creator and
requires the new pipe to deliver `a` through the shared namespace.

The applicable contracts are `kernel.el1.ipc-fd-authority` and
`kernel.el1.ipc-lifecycle` (see `conformance-contracts/contracts/el1-ipc-*.toml`).
Linux pipe2 requires two new descriptors in the caller's namespace, independent
descriptor close-on-exec flags, nonblocking status shared by aliases of each
endpoint's description, and no new descriptors after a failed call. Reader
and writer have distinct open descriptions. Internal admission contention is an owned
wait, not a guest errno. These contracts do not yet bind native creation or
its deterministic work budgets; existing lifecycle proofs exclude creation.

## Existing owners

`carrick-fd-core::SlotTableTransaction::install_pair` already publishes two
prepared descriptions atomically. It chooses both slots and retains both
references before publication. Its scope must not contain guest copy, service
calls, suspension, or storage provisioning. Reuse it rather than introducing
another numeric-fd allocator.

`Authority::create_pinned` supplies unpublished description custody. A pipe
preparation owner must account for the reader and writer references even when
the second description cannot be allocated: an endpoint not yet represented
by a description still needs release. Releasing the last pin returns its
description backing for canonical object release.

`IpcRegion::create_pipe` may detach an undersized retained ring into its
`retired` output. `HostIpc::create_pipe` returns that extent to its private
ring allocator and replenishes first-write ring stock. A ring caller cannot
discard the receipt or assume default-capacity storage is always available.
A larger retained ring already fits a smaller pipe; the reverse needs a
replacement/reclaim owner. Repeated create/close must demonstrate bounded
storage through reuse and reclamation.

Object and description growth currently belongs to `HostIpc`: it enforces
configured `IpcLimits` and records `IpcGrowth`. Calling the raw region growth
methods from the ring would bypass that authority. Initial segment exhaustion
must request canonical growth and retain preparation across that request.

## Required publication transaction

The native route needs an owned creation continuation, not just a new
descriptor-family classifier arm. It must retain:

- the exact task/table generation and cancellation authority;
- the prepared endpoint descriptions and any unwrapped endpoint;
- storage replacement/reclaim receipts and pending growth requests;
- the whole eight-byte destination preparation and final publication result.

`ProcessNative::complete_copyout` currently retains bytes, offset and result.
It has no descriptor rollback owner. Installing the pair and then calling it
can leak descriptors on a genuine output fault. Copying fd numbers first is
also insufficient: subsequent publication can refuse or choose different
slots. Numeric close-based rollback after publication could close a reused
descriptor belonging to another thread.

Before enabling routing, choose and prove one protocol: secure the complete
output with an authority whose final write cannot fault, retaining cancellation
custody through pair installation; or extend the owned reservation/continuation
protocol so pair publication, output completion and abort have one owner.
Neither option may hold the table mutation lock across guest memory work.
Secure output only for the bounded final commit, after growth and other waits.
A secured effect cannot survive suspension: retain restartable preparation
metadata and reacquire the authority after waking. Busy retains the operation
on the existing holder's release notification.

## Reuse by #1506

The shared mechanism should expose prepared-description admission, canonical
growth requests, atomic slot publication and explicit abort. Eventfd, epoll
and timerfd can use single-description publication with that same custody;
pipe2 uses atomic pair publication and additionally owns two endpoint refs and
its output record. Linux flag decoding stays in the shared Linux personality,
with ISA adapters providing only ordinal/frame and memory mechanics. This
avoids separate ARM and x86 creation authorities.

Required VM-free tails include second-description allocation refusal, one
remaining descriptor slot, configured growth ceilings, an output spanning an
unwritable page, cancellation during preparation, Busy once then success,
small retained storage reuse/replacement, repeated create/close, and a creator
forking a reader while its original parent remains live. Then run the exact
`carrick run` shell reproduction on the signed artifact. VM-free forwarding
evidence alone does not satisfy that CLI acceptance.

## Independent review

A fresh read-only GPT-6.1 Sol review identified publication before fallible
output as P0, and storage custody, growth policy and partial-preparation
rollback as P1 requirements. This investigation rechecked these claims against
`fd-core/src/lib.rs`, `el1-abi/src/ipc.rs`, `kernel/src/el1_ipc.rs`, and
`el1-linux/src/native_process_runtime{.rs,/service.rs}`. No production fix was
submitted for review in this investigation.

Kept: the earlier worker's two red witnesses and their positive data-transfer
tails. Ported: none (the admitted-main rebase required no conflict resolution).
Dropped: none. No routing, crossing allowlist, budgets, timeouts or concurrency
policy changed.
