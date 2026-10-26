/*
 * What stops an idle executor before its switched record is relinquished?
 * Run with carrick trace --script PATH -- --external /bin/bash
 * scripts/test-signed.sh carrick-embed TEST --exact --nocapture.
 *
 * ABI: hvpatch-executor-failure(u32 executor, C string error), as declared
 * in carrick-observability; trace-witness-exit carries raw wait status.
 * A failure row is required to qualify the error string live. Lifecycle
 * events only count and start the guest bound; no hot-path output or stacks.
 * Perturbation: USDT enrollment and lifecycle counting before failure;
 * the failure itself prints its error and host stack. Not timing evidence.
 */
#pragma D option quiet
#pragma D option strsize=2048

BEGIN { started = timestamp; guest_started = 0; failures = 0; errors = 0; }

carrick*:::hvpatch-guest-lifecycle
/pid == $target || progenyof($target)/
{
    guest_started = guest_started == 0 ? timestamp : guest_started;
}

carrick*:::hvpatch-executor-failure
/pid == $target || progenyof($target)/
{
    failures++;
    printf("executor-failure pid=%d host_tid=%d executor=%d error=%s\n",
        pid, tid, arg0, copyinstr(arg1));
    ustack(32);
}

dtrace:::ERROR { errors++; }

carrick*:::trace-witness-exit
/pid == $target/
{
    printf("witness-exit status=%d failures=%d errors=%d\n", arg0, failures, errors);
    exit(failures == 0 || errors != 0 ? 1 : 0);
}

tick-1s
/(guest_started != 0 && timestamp - guest_started >= 120000000000) ||
 (guest_started == 0 && timestamp - started >= 300000000000)/
{
    printf("capture-timeout failures=%d errors=%d\n", failures, errors);
    exit(1);
}
