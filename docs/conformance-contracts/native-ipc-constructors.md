# Native child IPC constructors (#1506)

This is a red-first checkpoint for `kernel.el1.ipc-fd-authority`, not a
constructor implementation or an acceptance claim. The four
`serial_host_native_fork_children_create_*_in_their_own_tables` bindings
fork two children through `NativeProcessRuntime` and call the production
`dispatch_syscall_with_native` entry with a real ARM trap frame. Both
children and their parent remain live. Each binding requires a ring answer,
CLOEXEC on the allocated descriptors, no publication into the parent table,
and distinct backing identities for the two children's newly created objects.
The pipe result is copied from the user buffer separately after each call.
These tests deliberately remain red until the corresponding ring service exists.

## Root cause

`serve_ipc_with_signals` admits read, write and epoll wait, not constructors.
`service_owner` classifies the four constructors as `RingOwed`, through their
Temporary crossing declarations. No constructor family serves that debt.
The production `native_unstaged_exit` asks `unclaimed_native_syscall` before
capturing a crossing: a fork child gets counted ENOSYS (38), while the root
retains the carrier route. This is an absent ring implementation, not a
missing inherited permission. Changing the child to a root or widening the
crossing policy would select the wrong process authority.

The root's carrier dispatcher already implements `pipe2` in `fs/pipe.rs`,
`eventfd2` in `net.rs`, `epoll_create1` in `net/epoll_ops.rs` and
`timerfd_create` in `time.rs`. Pipe, eventfd and zone epoll use shared IPC
objects underneath those host wrappers. Timerfd instead owns host
`TimerFdState`, including the creating container's clock domain. The root
therefore succeeds through a service the native child cannot use; it does
not already have an in-ring constructor.

## Required implementation

Serve constructors before the unclaimed-native boundary, in shared Linux
code used by both ISAs. Resolve the executing task's exact table, including
borrowed root tables, without inheriting a parent table or host task.
Validate flags and clocks before allocating. Preserve current Linux errors,
zone ceilings, elastic storage growth, and bounded work. Capacity misses
are not new fixed limits; contention retains the operation and enrolls on
the authority's release notification.

Pipe construction must prepare owner-aware user output before effects, use
`SlotTableTransaction::install_pair` for atomic publication, and settle both
endpoint descriptions on failed publication or genuine copyout fault.
Allocation/cleanup must account for retained pipe storage; the current
`create_pipe` API explicitly returns storage requiring host retirement.
No object/table lock may survive user copy, service, or suspension.

Timerfd needs one shared, pointer-free timer authority, with host users moved
to it rather than a ring-only copy beside `TimerFdState`. Preserve the
creator's clock-domain identity, frozen/deterministic/scaled-clock behavior,
set/get/read, expiry counts, scheduler deadlines, epoll membership and final
release. Any IPC record-layout change must update the ABI identity. Expiry
must respect the existing member-before-epoll lock order, publish after
unlock, and use scheduler notifications without a host readiness pipe or
polling. A dormant create-only timer is not parity with the root service.

The VM-free witnesses do not prove guest instructions, backing supply,
signed ARM execution, x86 execution or Go build. Those higher-layer bindings,
constructor refusal/rollback schedules and deterministic work budgets remain
required before acceptance.
