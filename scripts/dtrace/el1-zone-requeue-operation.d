#!/usr/sbin/dtrace -qs
/*
 * Did a host boundary find the loaded thread's own zone record switched
 * back in by EL1 at the SVC of a pending object operation (pipe/eventfd
 * read or write) that never re-executed, and requeue it?
 *
 * WHAT: prints each `el1-zone-requeue-operation` firing and counts them by
 * slot and exit kind. Before `ZoneTables::release_current` requeued such a
 * record, the host left it switched in (`OnCpu`) on the slot, and the
 * thread's next load there died with "EL1 zone slot N still held threads
 * when a task was loaded on it" (current = the thread's own record, object
 * operation pending, handback Resumed). Each firing is one such window.
 *
 * The exit kind tells which ordering opened the window:
 * - syscall=1: EL1 switched the record in inside the same call (the thread
 *   parked its operation in `ipc::run`, the object became ready, `run_next`
 *   switched it straight back in) and, with host work pending, left with
 *   `ServedWithWork` carrying the record's unexecuted SVC frame; the
 *   descriptor drain in `drain_before_el0` can do the same.
 * - syscall=0: the vCPU stopped at EL0 before the restored SVC ran (an IRQ
 *   kick forwarded by `Sched::interrupt`, or a host-cancelled run).
 *
 * ABI (carrick USDT, added 2026-10-01): el1-zone-requeue-operation:
 * u32 zone slot, u32 exit kind (1 syscall mailbox, 0 EL0 boundary),
 * u64 zone record id. Positive control: `vcpu-irq-kick`.
 *
 * TARGETING: `pid == $target || progenyof($target)`, under `dtrace -Z`.
 *
 * BOUND: tick-30s exits. Zero firings is a valid result on a run that never
 * hit the window (a few percent of `pidtaskdomain` probe runs).
 *
 * PERTURBATION: one printf per firing; the path is rare.
 */

#pragma D option quiet
#pragma D option zdefs

carrick*:::el1-zone-requeue-operation
/pid == $target || progenyof($target)/
{
    printf("requeue-operation pid=%d slot=%u syscall=%u record=%u\n", pid, arg0, arg1, arg2);
    @requeued[arg0, arg1] = count();
}

carrick*:::vcpu-irq-kick
/pid == $target || progenyof($target)/
{
    @irq_kicks = count();
}

tick-30s
{
    exit(0);
}

dtrace:::END
{
    printa("slot %u syscall %u: %@d requeued\n", @requeued);
    printa("vcpu-irq-kick exits: %@d\n", @irq_kicks);
}
