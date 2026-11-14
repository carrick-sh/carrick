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

## Return-path audit (round 2)

No abort cause is established by this audit. There is no single existing
futex-result write site: immediate family, scheduler restoration, native service
and carrier completion each publish registers. A family-only observer cannot
cover this surface.

| Completion path | Production owner / publication | Value reaching x0 (rax on x86) |
| --- | --- | --- |
| ARM immediate private/shared-private wait | Linux `sched::serve_futex`, EL1 Linux `sched::Adapter`, substrate `Sched::wait_word_with` | mismatch -11; pending signal -4; realtime zero mask -22; genuine word-copy fault -14 through `FamilyCompletion::Complete`; otherwise parks |
| ARM immediate wake | substrate `Sched::wake_word`, Linux adapter | number actually woken; invalid key -22 |
| Parked wait, selected in ring | substrate `Sched::load` after `cpu.load` | `ResumeAction::Returned` overrides `SwitchedIn.result`; otherwise scheduler result: successful wake 0, timer -110, signal -4. RetrySavedSyscall/RetrySyscall install no result and preserve arguments |
| Switched-away caller | Linux `transfer_effect` / completion `finish` | `Switched(result)` is the successor's register, never a completion for the departing operands; the departing record remains parked |
| WakeEffects / timer / interruption | scheduler owner publishes queued result; substrate load or host executor consumes it | wake 0; timer's retained timeout result -110; interrupted parked futex -4. WakeEffects itself does not write a guest register |
| Native process futex (including x86) | `native_process_runtime/futex.rs`, dispatch `futex` | shared Linux policy's immediate results; native wake count; true copy fault -14; ownership wait retains operation, no errno; parked completion returned by native lifecycle |
| Native service reply / resumed crossing | `native_service_user_return` | exact `NativeResume::Returned` result. EINTR restart marker retains original arg0 in FAR; signal owner decides restart, rather than treating a retry as a completed futex |
| Unclaimed native descendant | `refuse_unclaimed_native_syscall` | counted -38; no host route. Root/unowned may retain host route |
| Crossing-policy refusal | personality dispatch `finish` / `evaluate_host_crossing` | policy installs -38; not necessarily passed through `PendingFamilies::futex` |
| Forwarded root / host-owned continuation | kernel `dispatch/futex.rs`, runtime `ThreadedVcpuLoop::complete_returned` | exact Returned value or negative Linux errno; IPC reload writes x0 and advances PC, normal completion uses complete_native_signal_return/complete_syscall |
| Single-thread carrier completion | runtime `complete_single_threaded_syscall` | exact dispatcher value through SyscallTrap::complete_syscall |
| Robust-list registration / futex_waitv | independent syscall classification / kernel dispatch | not a call to the EL1 futex family; refusal can be -38, host dispatch has its own validation and wait-vector result |

The in-ring decoder admits PRIVATE WAIT, positive WAKE, positive nonzero-mask
WAKE_BITSET, and indefinite WAIT_BITSET (including CLOCK_REALTIME). It converts
shared spellings only after private-anonymous MM authentication. PI, requeue,
WAKE_OP, non-null absolute bitset deadlines, and other combinations are outside
this decoder. That establishes possible refusal paths, not that Node uses them.
The host kernel dispatcher additionally implements PI and vector operations;
a ring refusal and a root host route are therefore different cases.

A capture must keep original operands until the owning completion, exclude
scheduler replay/preempted already-completed frames, and observe the carrier as
well as EL1. The positive-28 control alone proves none of these paths erroneous.
