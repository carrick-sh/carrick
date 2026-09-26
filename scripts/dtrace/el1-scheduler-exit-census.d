#!/usr/sbin/dtrace -qs
/*
 * Which host exits remain while guest threads are scheduled in-guest (EL1
 * plan 1c), and who caused them.
 *
 * WHAT: counts, for the traced carrier tree, every vCPU `CANCELED` exit by
 * exception level and whether the run loop resumed it in place (an EL1
 * critical section), every host kick (`hv_vcpus_exit`) with the user stack
 * of the kicker, every `hvc #4` kick exit taken at an EL0 boundary, and every
 * forwarded syscall by Linux syscall number (the mailbox transport probe).
 * Read it against the zone counters of the same run: a steady-state in-guest
 * handoff should produce none of these per round trip.
 *
 * ABI (carrick USDT, spellings as the 1b/1a scripts qualified them live on
 * macOS 27.2 / M4, signed binaries of 2026-09):
 * - vcpu-canceled: u64 vCPU, u64 PC, u32 exception level, i32 resumed-in-EL1.
 * - vcpu-kick: u64 vCPU handle, i32 handle-valid flag, i32 hv_vcpus_exit rc.
 * - vcpu-irq-kick: u64 interrupted EL0 PC (the `hvc #4` decode).
 * - hvf-syscall-transport: u32 transport, u64 unused, u32 register reads,
 *   u32 system-register reads, u64 unused (one per forwarded syscall).
 *
 * TARGETING: `pid == $target || progenyof($target)`, under `dtrace -Z`
 * (carrick trace arms probes of not-yet-started processes).
 *
 * BOUND: tick-30s exits normally; the aggregations print at END. Zero kicks
 * AND zero canceled exits is a valid result (the point of the increment), so
 * the positive control is the transport probe: a carrier that forwarded no
 * syscall at all did not run, and END says so instead of printing an empty
 * census.
 *
 * PERTURBATION: one aggregation update per exit and per kick, plus a user
 * stack walk per kick. Diagnostic only; do not cite its timings.
 */

#pragma D option quiet
#pragma D option zdefs

dtrace:::BEGIN
{
    forwarded = 0;
    printed = 0;
}

carrick*:::vcpu-canceled
/pid == $target || progenyof($target)/
{
    @canceled[arg2 == 0 ? "el0" : "el1", arg3 != 0 ? "resumed" : "surfaced"] = count();
}

carrick*:::vcpu-kick
/pid == $target || progenyof($target)/
{
    @kicks[ustack(12)] = count();
    @kick_total = count();
}

carrick*:::vcpu-irq-kick
/pid == $target || progenyof($target)/
{
    @irq_kicks = count();
}

carrick*:::hvf-syscall-transport
/pid == $target || progenyof($target)/
{
    forwarded++;
    @forward_threads[tid] = count();
}

/*
 * Kicker stacks are symbolized when printed, which needs the carrier alive:
 * print them at 2 s (run the workload for longer than that).
 */
profile:::tick-2s
/!printed/
{
    printed = 1;
    printa("kicker (at 2 s) %k count %@d\n", @kicks);
}

profile:::tick-30s
{
    exit(0);
}

dtrace:::END
{
    printf("forwarded syscalls: %d\n", forwarded);
    printa("canceled %-4s %-9s %@d\n", @canceled);
    printa("hvc4 kick exits %@d\n", @irq_kicks);
    printa("host kicks %@d\n", @kick_total);
    printa("kicker %k count %@d\n", @kicks);
    printa("forwarding host thread %d: %@d\n", @forward_threads);
}

dtrace:::END
/forwarded == 0/
{
    printf("NO FORWARDED SYSCALL: the carrier did not run under the trace\n");
    exit(1);
}
