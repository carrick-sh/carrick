/*
 * Signal delivery at sleep admission, measured only at restart decisions.
 * ABI: signal-restart-decision arg0 guest tid, arg1 signum, arg2 syscall
 * number, arg3 return value, arg4 boundary/EINTR/SA_RESTART/restartable bits.
 * Source ABI checked against probes.rs and signal-restart-decision.d;
 * Qualified live on macOS arm64 2026-09-14: SIGINT/clock_nanosleep
 * reported tid=4, signal=2, nr=115, retval=-4, bits=3; two decisions,
 * zero DTrace errors, terminal exit 0. Empty captures remain failures.
 * Perturbation: one record per delivered caught signal; timing-sensitive
 * behavior can still change. This is ordering evidence, not a timing claim.
 * Bound: 45 seconds permits the reduced Python child's 30-second sleep to
 * finish before normal detach. Zero decisions and DTrace errors fail closed.
 */
#pragma D option quiet

dtrace:::BEGIN { decisions = 0; errors = 0; }
carrick*:::signal-restart-decision
/pid == $target || progenyof($target)/
{
    decisions++;
    printf("SSA1|ts=%llu|host_pid=%d|tid=%d|signal=%d|nr=%d|retval=%d|bits=%d\n",
        timestamp, pid, arg0, arg1, arg2, arg3, arg4);
}
dtrace:::ERROR { errors++; }
tick-45s
{
    printf("SSA1|end|decisions=%d|errors=%d\n", decisions, errors);
    exit(decisions > 0 && errors == 0 ? 0 : 1);
}
