/*
 * tier-d-mach-invalid-receive.d — prove whether a stranded Tier-D exception
 * RPC coincides with mach_msg_server returning MACH_RCV_INVALID_DATA.
 *
 * Provider ABI qualified from Carrick's generated USDT declaration on
 * 2026-08-08: native-tierd-exception(phase, host_pid, a, b, c, d), copied
 * scalars. Phase 14 is emitted after mach_msg_server returns: a=status,
 * b=prior restart count, c=receive port-set name, d=1 iff Carrick retries the
 * receive-buffer failure. MACH_RCV_INVALID_DATA is 0x10004008.
 *
 * This arms one low-frequency USDT probe under `dtrace -Z`. It is attribution
 * evidence, not performance evidence. Let the 150-second bound end naturally;
 * do not kill the DTrace consumer while a native tracee continues.
 *
 * Usage:
 *   sudo dtrace -Z -q -s scripts/dtrace/tier-d-mach-invalid-receive.d \
 *     > /tmp/tier-d-mach-invalid-receive.out
 */

#pragma D option quiet
#pragma D option strsize=256

dtrace:::BEGIN
{
    printf("TDMACHI1|event=begin|time=%Y\n", walltimestamp);
}

carrick*:::native-tierd-exception
/arg0 == 14/
{
    printf("TDMACHI1|event=server-return|ts=%d|pid=%d|wire-pid=%d|status=%#x|prior-restarts=%d|port-set=%#x|retry=%d\n",
        timestamp, pid, (int)arg1, arg2, arg3, arg4, arg5);
}

tick-150s
{
    printf("TDMACHI1|event=bound|seconds=150\n");
    exit(0);
}

dtrace:::END
{
    printf("TDMACHI1|event=end|time=%Y\n", walltimestamp);
}
