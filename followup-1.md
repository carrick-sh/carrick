# x86 CPL0: a sibling thread spinning or yielding on CPU 0 starves the home thread

Found while building the #1482 P0-3 KVM witness (`native_cow_retire_race.S`, PR #2250).

The root process (the home record of CPU 0) cloned a CLONE_THREAD worker. If the worker
ran on CPU 0 and then looped, either in a user-mode `pause` spin or in a
`sched_yield`/fixture-syscall loop, the leader never resumed:
- its `clone` return did not complete for 1M yields (about 130 s) or 2^30 pauses
  (about 20 s);
- vCPU 1 sat in HLT (`ioctl KVM_RUN` sleeping, with no kvm_exit samples), and vCPU 0
  ran only the worker's syscall loop (`perf record -e kvm:kvm_exit`).

The leader made progress only after the worker exited. Two live threads in one MM
should both make progress: `sched_yield` from the worker should run the home thread,
or the idle CPU should take the non-home worker.

Plan: reproduce with a two-thread fixture where the worker yields in a loop and the
leader must return from clone; inspect `switch_in_full` and steal placement for the
home record's host-side continuation.
Acceptance: the leader resumes while the worker yields, on real KVM.
Run ids: r7-red-12, r7-red-13 (exit 100: the leader never left clone), r7-green-11
(hang: vCPU 0 in the worker's yield loop, vCPU 1 idle).
