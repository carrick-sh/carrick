#!/usr/sbin/dtrace -qs
/*
 * hvpatch-carrier-sched-share.d — how much of one HVPatch carrier's CPU goes
 * to scheduling guest threads on the host (executor sleep/wake, run-queue and
 * generation locks, condvars) versus guest execution and syscall service.
 *
 * (a) What it measures. On-CPU samples of the traced carrier, each keyed by
 * its kernel stack (the leaf frames name psynch/condvar/turnstile work) and its
 * user stack (the owning Carrick frame: `hv_vcpu_run` is guest execution,
 * `Scheduler::take`/`take_row_bound`/`idle_condvar` is an executor looking for
 * work, `Scheduler::wake`/`enqueue` is a waker, `publish_event` is a
 * continuation completion). EL1 increment 1d used it to size the executor
 * sleep/wake share before and after the host executors became per-vCPU
 * drivers. Bucket offline by the first owning user frame, leaf to root, and
 * report the kernel-only samples (no user stack) separately.
 *
 * (b) Provider ABI, qualified live on Darwin/arm64 (macOS 27.2, M4,
 * 2026-09-25): `profile-997` fires per CPU with `pid`/`tid` of the
 * interrupted thread; `arg0` is the kernel PC (non-zero when the sample
 * interrupted the kernel), `arg1` the user PC. `ustack()` is trustworthy only
 * because `.cargo/config.toml` forces frame pointers. Symbols resolve lazily at
 * print time, so the aggregation prints in 1-second slices while the carrier
 * is alive (see hvpatch-carrier-user-cpu-ranking.d (d)); sum the slices.
 * Guest-executing samples land in the HVF vCPU-run call.
 *
 * Attach to the VM carrier (for `carrick run --rm`, the CLI process itself):
 *   sudo dtrace -qs scripts/dtrace/hvpatch-carrier-sched-share.d -p <carrier>
 * or start it with `-c`.
 *
 * (c) Perturbation: moderate (one 20-frame user and 12-frame kernel unwind
 * per sample at 997 Hz per CPU). Shares are citable only against the same
 * instrument; absolute CPU and wall under this script are not.
 */

#pragma D option quiet
#pragma D option bufsize=96m
#pragma D option aggsize=96m

dtrace:::BEGIN
{
    started = timestamp;
    samples = 0;
}

profile-997
/pid == $target/
{
    samples++;
    @stacks[arg0 != 0 ? "K" : "U", stack(12), ustack(20)] = count();
}

profile:::tick-1sec
{
    printf("HVPSCHED|slice|samples=%d\n", samples);
    printa("HVPSCHED|stack|%s%k%k|%@d\n", @stacks);
    trunc(@stacks);
}

proc:::exit
/pid == $target/
{
    exit(0);
}

profile:::tick-1sec
/timestamp - started > 120 * 1000000000/
{
    exit(0);
}

dtrace:::END
{
    printf("HVPSCHED|end|samples=%d|empty=%d\n", samples, samples == 0);
    printa("HVPSCHED|stack|%s%k%k|%@d\n", @stacks);
}
