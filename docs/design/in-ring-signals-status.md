# Shared in-ring signals: review scope and remaining owners

The ARM host still owns signal delivery and rt_sigreturn. ARM syscall 139
must remain unported; its dormant native frame builder/restorer is checked
against canonical ABI records in VM-free tests. No signed ARM runtime
verification was possible on the Linux worker.

The x86 witnesses compare the same static ELF against native Linux, with
five-second process bounds. They cover preserved syscall and FP/SIMD state,
fault fixup and real fault registers, child-specific actions, forced child
SIGSEGV, nested masks, reset-hand, alternate-stack overflow, owned suspend
and wait continuations, concurrent finite deadlines, thread identity, busy
child termination, wait4 interruption/restart, SIGCHLD payloads, and a
self-targeted SIGABRT without a written core. The latter exercises tgkill
and default abort delivery, not libc's internal abort implementation.

These are named integration dependencies, not completed signal semantics:

| Requirement | Owning dependency | Retained evidence |
| --- | --- | --- |
| H2 repeated child suspend/wait | Shared child-MM retirement must return reusable stock | Three-round sigsuspend/sigwait and stock-reuse KVM witnesses |
| H4 blocked read interruption | Director-owned x86 in-zone pipe/fd-table lane; pipe2 is currently ENOSYS | `mounted_static_x86_signal_kills_reading_child_matches_native` |
| H6 stop/continue and SIGKILL member retirement | Shared process-owner lifecycle and wait events; native wait event type is still empty | `mounted_static_x86_signal_stop_continue_matches_native` |
| M3 signal permissions, M4 RLIMIT_SIGPENDING, SIGCHLD si_uid | Identity credentials and per-process rlimits in PR #130 | No fabricated credential or quota owner introduced |
| M5 reset_for_exec | Identity/exec lane must admit a real x86 exec successor and call the existing reset hook | No new exec host crossing introduced |
| M7 production WithWork runtime | x86 fd-table executor lane must own the production WORK_PORT handler | `signal_delivery_waits_for_the_owned_completion_ledger` proves ordering only |

The director accepted these owner boundaries for review. The full KVM
suite must still report each red explicitly. The three origin/main reds
(anonymous ELF, adjacent page journal, and arch_prctl) are separate baseline
failures; signal witnesses are not skipped or weakened to hide dependencies.

Pidfd signals retain the previous lane routing until in-ring pidfds exist:
ARM uses the old forwarding route, while x86 retains its existing unported
ENOSYS route. No constant EBADF or extra x86 host crossing is introduced.

Early root-only forced-fault tests were insufficient: carrier-wide death
looked like correct SIGSEGV. Child witnesses now require the parent to
survive and reap the faulting child. Production fixture dispatch remains
intact; the canonical supervisor image extent was increased after exact
link-map measurements proved that retained code exceeded the former cap.
