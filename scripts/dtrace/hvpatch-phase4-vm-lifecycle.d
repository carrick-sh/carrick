#!/usr/sbin/dtrace -qs
/*
 * Count Hypervisor.framework VM lifecycle calls made by one hvpatch runtime.
 *
 * Provider ABI: carrick*:::vm-lifecycle arg0 is 0=create-attempt,
 * 1=create-success, 2=destroy-attempt, or 3=destroy-success; arg1 is the create
 * admission class, or -1 for destroy. The target may be a namespace supervisor,
 * so the predicate follows its Carrick descendants. Per-host-pid aggregates let
 * an exec replacement be distinguished from a guest fork into another process.
 *
 * Perturbation: one low-frequency Carrick lifecycle probe only.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    creates = 0;
    destroys = 0;
    create_attempts = 0;
    destroy_attempts = 0;
    errors = 0;
    bounded = 0;
}

carrick*:::vm-lifecycle
/pid == $target || progenyof($target)/
{
    create_attempts += arg0 == 0;
    creates += arg0 == 1;
    destroy_attempts += arg0 == 2;
    destroys += arg0 == 3;
    @by_pid[pid, arg0, arg1] = count();
}

dtrace:::ERROR
{
    errors++;
}

proc:::exit
/pid == $target/
{
    exit(0);
}

profile:::tick-1sec
/timestamp - machtimestamp > 90 * 1000000000/
{
    bounded = 1;
    exit(0);
}

dtrace:::END
{
    printf("HVPATCH4VM|end|create_attempts=%d|creates=%d|destroy_attempts=%d|destroys=%d|bounded=%d|errors=%d\n",
        create_attempts, creates, destroy_attempts, destroys, bounded, errors);
    printa("HVPATCH4VM|pid|pid=%d|operation=%d|admission=%d|count=%@d\n", @by_pid);
}
