# Futex return attribution (#2288)

The production ARM syscall entry can park a futex waiter and return a different
thread's frame. `FamilyCompletion::Switched(result)` carries that successor's
register result, not the parked syscall's result. Observers must not combine
that scalar with the departing thread's futex operands or execution binding.

`production_futex_wait_switch_keeps_successor_result_separate_from_wait_result`
exercises `dispatch_syscall_with_regions` with two live scheduler records. One
thread calls op 393 (`WAIT_BITSET | PRIVATE | CLOCK_REALTIME`) without a timeout.
Its successor has a preempted completed write with result 28. Dispatch installs
the successor's syscall ordinal, identity, PC and result 28 while the futex
caller remains parked. The successor wakes that caller and parks itself; the
original futex then returns zero, while only the waker received count one.
Exactly two parks and two switches occur. This is a control for the positive-28
lead, not a red-first reproduction of the Node abort or a repair of it.

The sampler in unmerged #2272 captures original operands/binding before futex
dispatch and includes `Switched` among completions it records. It can therefore
report `op=393 result=28` without any futex returning 28. The historical sample
alone cannot establish which successor ran; that needs a capture of both
execution bindings and frame ordinals before and after selection.

Linux authority is futex(2): a successfully woken WAIT returns zero, while WAKE
returns the number woken. The existing `kernel.el1.futex-handoff` contract owns
the production-entry control and its two-switch bound. This slice changes no
production behavior, work budget or routing. Signed Node/HVF capture remains
necessary to identify the actual rejected futex result. In particular, an
immediate-family sampler does not cover delayed wait completion at scheduler
load or host handback. Zero samples from it do not prove those paths correct.
