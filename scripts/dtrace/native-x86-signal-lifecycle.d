#!/usr/sbin/dtrace -qs
/*
 * Kernel-provider-only signal lifecycle trace for one already-running native
 * Carrick process tree. This never enables pid/fasttrap/USDT probes and is safe
 * to detach from a continuing tracee.
 *
 * Usage:
 *   dtrace -q -s scripts/dtrace/native-x86-signal-lifecycle.d ROOT_PID
 */

#pragma D option quiet

BEGIN
{
    tracked[$1] = 1;
    printf("SIGNAL_TRACE root=%d\n", $1);
}

proc:::create
/tracked[pid]/
{
    tracked[args[0]->p_pid] = 1;
}

proc:::signal-send
/tracked[args[1]->p_pid]/
{
    printf("SIGNAL_SEND sender=%d sender_exec=%s target=%d signal=%d\n",
        pid, execname, args[1]->p_pid, args[2]);
}

proc:::exit
/tracked[pid]/
{
    tracked[pid] = 0;
}

proc:::exit
/pid == $1/
{
    printf("SIGNAL_TRACE_EXIT root=%d\n", $1);
    exit(0);
}
