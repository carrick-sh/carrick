/*
 * signal-restart-decision.d — why did an interrupted syscall NOT restart?
 *
 * WHAT IT MEASURES
 *   One line per SA_RESTART restart decision, restarted or not. Whether an
 *   interrupted syscall restarts is four conditions ANDed into a single
 *   boolean in `vcpu_loop::signal::deliver_pending_signal`; from outside they
 *   collapse into "the guest saw EINTR anyway". This prints them separately:
 *
 *     boundary   the signal was injected at a syscall boundary (not a kick),
 *                which is the only path that can rewind the PC to the `svc`
 *     eintr      the interrupted syscall's retval was -EINTR
 *     sa_restart the handler's sigaction carried SA_RESTART
 *     restartable the syscall number is in `is_restartable_syscall`
 *
 *   All four must be 1 (predicates == 15) for the syscall to be restarted.
 *
 * PROVIDER ABI (qualified live on macOS 27 / Apple Silicon, 2026-08-17)
 *   carrick*:::signal-restart-decision
 *     arg0 tid        guest thread id the signal is being delivered TO
 *     arg1 signum     Linux signal number
 *     arg2 syscall_nr the trap's last syscall number, or -1 if it carried none
 *     arg3 retval     the interrupted syscall's return value
 *     arg4 predicates bit0 boundary, bit1 eintr, bit2 sa_restart, bit3 restartable
 *
 *   Fired from `crates/carrick-runtime/src/vcpu_loop/signal.rs`; declared in
 *   `crates/carrick-observability/src/probes.rs`. The `carrick*` wildcard is
 *   load-bearing: the guest runs in the VM carrier, which is not necessarily
 *   the process you launched.
 *
 * PERTURBATION
 *   Negligible. It fires once per signal DELIVERY, not per syscall, so even a
 *   signal-heavy workload produces tens of events. Safe to leave armed while
 *   reproducing a timing-sensitive race — it was used to diagnose one.
 *
 * WHAT IT FOUND (the reason it exists)
 *   libuv's `eintr_handling` failed ~half its runs and looked exactly like a
 *   missing entry in the restartable set. The stream showed the only SIGUSR1
 *   decision in a failing run was
 *
 *     tid=16 signum=10 nr=129 retval=0 predicates=5 [boundary=1 eintr=0 ...]
 *
 *   nr=129 is `kill` — the signal was delivered to the thread that RAISED it,
 *   at its own syscall boundary. The blocked reader that returned -EINTR never
 *   appears in the stream, because no signal was ever delivered to it. That is
 *   a spurious EINTR, and no amount of SA_RESTART work could have fixed it:
 *   the restart path only runs when a signal IS delivered.
 *
 *   The lesson generalises. An ABSENT event is evidence here: if a thread
 *   surfaced EINTR and has no line in this stream, it was interrupted without
 *   delivery, which Linux never does.
 *
 * USAGE
 *   carrick trace -s scripts/dtrace/signal-restart-decision.d -- run <args...>
 *
 *   `carrick trace` auto-sudos; do not prefix it with sudo. Kill leftover
 *   `carrick run` processes first (scoped: scripts/sudo/kill.sh <run-id>).
 */

#pragma D option quiet
#pragma D option strsize=256

carrick*:::signal-restart-decision
{
	printf("tid=%d signum=%d nr=%d retval=%d predicates=%d [boundary=%d eintr=%d sa_restart=%d restartable=%d]\n",
	    arg0, arg1, arg2, arg3, arg4,
	    (arg4 & 1) ? 1 : 0,
	    (arg4 & 2) ? 1 : 0,
	    (arg4 & 4) ? 1 : 0,
	    (arg4 & 8) ? 1 : 0);
}

END
{
	printf("\n(no lines above means no signal was DELIVERED to any guest thread;\n");
	printf(" a thread that returned EINTR without a line here was interrupted\n");
	printf(" without delivery, which Linux never does.)\n");
}
