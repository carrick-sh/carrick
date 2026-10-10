# Shared in-ring signals: review scope and remaining owners

The ARM host still owns signal delivery and rt_sigreturn. ARM syscalls
129 through 139 and 240 must remain unported; its dormant native frame builder/restorer is checked
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
| M3 signal permissions, M4 RLIMIT_SIGPENDING, SIGCHLD si_uid | Signal permission/quota integration with identity credentials and per-process rlimits | No fabricated credential or quota owner introduced |
| M5 reset_for_exec | Identity/exec lane must admit a real x86 exec successor and call the existing reset hook | No new exec host crossing introduced |
| M7 production WithWork runtime | x86 fd-table executor lane must own the production WORK_PORT handler | `signal_delivery_waits_for_the_owned_completion_ledger` proves ordering only |

These owner boundaries do not waive new failing KVM tests. The full KVM
suite must still report each red or explicitly named dependency. The three reds named in the brief (anonymous ELF, adjacent page journal,
and arch_prctl) remain separate baseline failures. Full verification also
found stdout poll and the authority-refusal witness red on the preserved
origin/main plus private-ELF prerequisite artifact. Poll belongs to the
in-zone fd-table lane. The authority fixture now checks served action
installation/query and the exact reduced boundary counts, while retaining
its strict refusal-family journal assertion. The five dependency witnesses now carry named ignores after the identity
rebase, as recorded below; their comparisons and assertions remain intact.

Pidfd signals retain the previous lane routing until in-ring pidfds exist:
ARM uses the old forwarding route, while x86 retains its existing unported
ENOSYS route. No constant EBADF or extra x86 host crossing is introduced.

Early root-only forced-fault tests were insufficient: carrier-wide death
looked like correct SIGSEGV. Child witnesses now require the parent to
survive and reap the faulting child. Production fixture dispatch remains
intact; the canonical supervisor image extent was increased after exact
link-map measurements proved that retained code exceeded the former cap.

The wait4 interruption witness validates the actual sender from siginfo and
saved RIP/RAX for both valid signal orderings. A signal caught before wait4
admission permits an ordinary reap; an interrupted wait requires EINTR in
the saved context. `caught_signal_interrupts_an_already_parked_owned_child_wait`
provides the deterministic parked-continuation proof, including retained
restart context and no reap of the live child.

The public `carrick-abi` facade reexports the single canonical signal wire
records from its existing guest-safe `carrick-syscall-abi` leaf. The shared
substrate depends on that leaf, never the umbrella personality crate.
Linux frame encoding/decoding lives in EL1 personality modules; ISA modules
retain neutral machine state and privilege checks. The boundary gate was
red with 27 violations before this relocation and clean for all nine
substrate crates afterwards. No boundary exceptions were added.

## Named KVM dependencies after identity rebase

The complete KVM suite on `work/ring-identity` at `ab7caeb05` plus this
branch still failed the following five witnesses. At the director's
request they retain their native comparison assertions and carry explicit
`#[ignore]` reasons. These exact dependency strings belong in the PR body;
the director manages that body. Remove the corresponding ignores and run
these unchanged witnesses when each mechanism lands.

| Witness | Exact dependency / ignore reason | Green on `ab7caeb05`? |
| --- | --- | --- |
| `fork_reuses_retired_stock_matches_native` | x86 child-MM retirement | No: exit 11 |
| `signal_kills_reading_child_matches_native` | x86 in-ring pipe2/read fd-table continuations | No: exit 38 |
| `signal_sigsuspend_loop_matches_native` | x86 child-MM retirement | No: exit 11 |
| `signal_stop_continue_matches_native` | shared process-owner stop/continue wait events | No: exit 99 |
| `signal_wait_child_matches_native` | x86 child-MM retirement | No: exit 11 |

The pre-ignore full run is recorded at
`/tmp/ring-on-identity-full-kvm-red.log` (38 passed, 10 failed, 5 originally
ignored). Identity's fixture table grant derived from shared image GPA plus
size remains present. The obsolete cancellation revert was omitted during
rebase, so it cannot remove identity's landed boundary correction.

## Review dependency guards

`x86 group exit custody` owns multi-member signal termination. Until it
lands, default-fatal signals and forced SIGSEGV with `page.live() != 1`
end the run through an authenticated `NativeRunFailure` crossing: exit 125,
stderr naming `x86 group exit custody`, and the execution report's
`run_failure` physical crossing count. This is a guard, not a reachable
path today: x86 `CLONE_THREAD` is not admitted. The VM-free two-live-member
SIGTERM contract checks this guard without retiring shared memory. The KVM
two-thread witness carries `#[ignore = "x86 CLONE_THREAD admission"]`.
Once admission lands, remove that ignore; the witness expects the named
failure and must turn red when group exit custody lands, requiring a native
SIGTERM comparison instead.

`owned interrupt cancellation` owns signal interruption of zone-parked
futex/object waits. An IPI currently only reaches OnCpu/home-Free records;
it does not claim a parked operation. Signals remain queued and are checked
at the next actual return to userspace after the wait owner resumes it.
There is no bound for an indefinite wait without its natural wake; no
polling or timer was added to hide that limitation. Native child waits and
signal waits have their own owned interruption paths.

The x86 timer interrupt currently expires only admitted signal waits, so
its EAGAIN result is specific to that family. The x86 futex and object
adapters require an ARM frame and forward today; nanosleep has no in-ring
route. Before those waits move into CPL0, their timer completion must own
its operation-specific result (ETIMEDOUT for futex, or object continuation
expiry), rather than reusing the signal-wait errno.

The optional saved restart context is heap-owned only when a wait is
interrupted; an ordinary signal checkpoint no longer embeds a second full
register/XSAVE context. The VM-free entry-size budget failed before this
change and passes afterward. Linked-code inspection measures
`signal_user_return`'s static stack allocation at 6,272 bytes before and
4,096 afterward (`/tmp/ring-review-stack-sizes.json`). Other observed
allocations are page-fault policy 1,336 bytes, delivery 504 bytes, and frame
setup 1,336 bytes. These are individual static allocations, not a complete
call-graph bound. The x86 page-fault assembly retains its hardware/GPR frame
on the 4 KiB TSS stack, then moves XSAVE and Rust policy to the CPU's 64 KiB
syscall stack; the ARM 16 KiB stack estimate does not describe that path.

The full-suite signal rendezvous exposed a separate IRQ stack overflow:
`signal_irq_return` alone reserved 5,120 bytes, in addition to the IRQ
entry's 896-byte XSAVE scratch, on the 4 KiB TSS stack. It corrupted a
subsequent retained page-fault IRET frame. User-origin IRQs now retain only
the hardware/GPR frame on TSS and move XSAVE/Rust to the 64 KiB syscall
stack, matching page faults. Kernel-origin IRQs keep the interrupted
kernel stack so an outer syscall/fault operation cannot be overwritten.
The unchanged concurrent two-MM witness is the runtime regression test.

## ARM-visible scheduler changes awaiting the signed gate

The shared timer heap, `clear_current` clean-state decision via
`timer_deadline`, and removal of the single-timer-owner refusal are
ARM-visible changes retained by this branch. They require the director's
signed ARM `el1_` coverage for concurrent timed parks, record migration,
and executor exit while a foreign record owns a timer. The Linux worker's
VM-free scheduler evidence does not replace that signed coverage. Include
these three changes and the owed scenarios explicitly in the PR body.
