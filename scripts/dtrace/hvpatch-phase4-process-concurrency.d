#!/usr/sbin/dtrace -qs
/*
 * Measure cumulative process creation and peak live descendants for the
 * hvpatch Phase 4 cold-build workload.
 *
 * Provider ABI qualified on macOS 26.0.1 arm64: proc:::create fires in the
 * parent and args[0]->pr_pid is the new child PID; proc:::exit fires in the
 * exiting process.  Carrick USDT probes are armed with -Z by `carrick trace`.
 *
 * `peak_processes` is deliberately conservative: it includes the traced root
 * and any supervisor/control descendants, so it is an upper bound on the
 * number of simultaneously live guest VMs.  `creates` is cumulative and must
 * not be interpreted as concurrent VM demand.
 *
 * Perturbation: proc lifecycle and low-frequency Carrick fork/exec probes only;
 * this script does not instrument syscall or instruction hot paths.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    tracked[$target] = 1;
    live = 1;
    peak = 1;
    creates = 0;
    guest_forks = 0;
    execs = 0;
    root_exited = 0;
    errors = 0;
    bounded = 0;
}

proc:::create
/tracked[pid] && !tracked[args[0]->pr_pid]/
{
    tracked[args[0]->pr_pid] = 1;
    creates++;
    live++;
    peak = live > peak ? live : peak;
}

carrick*:::fork-post
/tracked[pid] && arg0 != 0/
{
    guest_forks++;
}

carrick*:::execve-loaded
/tracked[pid]/
{
    execs++;
}

proc:::exit
/tracked[pid]/
{
    tracked[pid] = 0;
    live--;
    root_exited = pid == $target ? 1 : root_exited;
}

proc:::exit
/root_exited && live == 0/
{
    exit(0);
}

dtrace:::ERROR
{
    errors++;
}

profile:::tick-1sec
/timestamp - machtimestamp > 90 * 1000000000/
{
    bounded = 1;
    exit(0);
}

dtrace:::END
{
    printf("HVPATCH4PROC|end|creates=%d|guest_forks=%d|execs=%d|peak_processes=%d|live=%d|bounded=%d|errors=%d\n",
        creates, guest_forks, execs, peak, live, bounded, errors);
}
