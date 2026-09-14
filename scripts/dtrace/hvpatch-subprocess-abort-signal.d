#!/usr/sbin/dtrace -qs
/*
 * Whole-subprocess abort-signal diagnostic. Derived from the qualified
 * hvpatch-kernel-signal-kick.d instrument; 45-second capture covers suite
 * context preceding test_run_abort. Diagnostic bound, not a gate deadline.
 *
 * Pinpoint a kernel-originated HVPatch signal that is published but loses its
 * vCPU kick, delivery drain, or guest-handler injection edge.
 *
 * WHAT: captures every nonzero Linux signum at the typed publication,
 * delivery, and injection probes; records every kick attempted while the vCPU
 * is in kernel context with its saved PC and exception level; and aggregates
 * vcpu-kick by handle-validity and raw hv_vcpus_exit return code.  Process
 * lifecycle records identify which member of the target tree produced each
 * edge.  This deliberately avoids per-fstat and per-syscall probes so the
 * signal-to-kick sequence remains the exact fault point.
 *
 * ABI (inherited from the live-qualified macOS/arm64 source
 * scripts/dtrace/hvpatch-sigchld-delivery.d, qualified 2026-08-15):
 * - signal-publish: i32 target Linux tid, i32 Linux signum, i32 kind
 *   (1 thread-directed, 0 process-directed).
 * - signal-deliver: i32 delivering Linux tid, i32 drained Linux signum
 *   (zero means no deliverable signal).
 * - signal-inject: i32 Linux signum, u64 saved PC, u64 new SP, u64 handler.
 * - kick-in_kernel: u64 saved guest PC, u32 exception level.  The exact
 *   spelling was verified from signed binary 43cef's DOF on 2026-09-14:
 *   Rust `kick__in_kernel` lowers the double underscore to a hyphen while the
 *   remaining single underscore is preserved.  The earlier inherited
 *   `kick-in-kernel` selector was invalid and produced zero events.
 * - vcpu-kick: u64 vCPU handle, i32 handle-valid flag, i32 raw
 *   hv_vcpus_exit return code.
 *
 * TARGETING: all carrick USDT clauses use
 * `pid == $target || progenyof($target)`.  proc start/exit records use the same
 * target tree to retain the host lifecycle around a lost edge.
 *
 * BOUND: tick-45s exits the consumer normally.  dtrace:::ERROR, zero nonzero
 * signal lifecycle events, or zero vCPU kicks fail closed from END.  These
 * last two checks are positive controls: an absent delivery or injection is a
 * valid diagnostic result after publication, so individual stages are not
 * required to be nonzero.
 *
 * PERTURBATION: diagnostic, not performance evidence.  It prints one line per
 * nonzero signal lifecycle event and in-kernel kick, and aggregates vCPU kick
 * outcomes.  It does not instrument the repeated guest syscall path.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    publishes = 0;
    delivers = 0;
    injects = 0;
    signal_events = 0;
    kernel_kicks = 0;
    vcpu_kicks = 0;
    errors = 0;
    bounded = 0;
}

proc:::start
/pid == $target || progenyof($target)/
{
    printf("HVPATCHKSIG1|proc-start|timestamp=%llu|host_pid=%d|host_tid=%d|ppid=%d\n",
        timestamp, pid, tid, ppid);
}

proc:::exit
/pid == $target || progenyof($target)/
{
    printf("HVPATCHKSIG1|proc-exit|timestamp=%llu|host_pid=%d|host_tid=%d\n",
        timestamp, pid, tid);
}

carrick*:::signal-publish
/(pid == $target || progenyof($target)) && (int32_t)arg1 != 0/
{
    publishes++;
    signal_events++;
    printf("HVPATCHKSIG1|publish|timestamp=%llu|host_pid=%d|host_tid=%d|target_tid=%d|signum=%d|kind=%d\n",
        timestamp, pid, tid, (int32_t)arg0, (int32_t)arg1, (int32_t)arg2);
}

carrick*:::signal-deliver
/(pid == $target || progenyof($target)) && (int32_t)arg1 != 0/
{
    delivers++;
    signal_events++;
    printf("HVPATCHKSIG1|deliver|timestamp=%llu|host_pid=%d|host_tid=%d|linux_tid=%d|signum=%d\n",
        timestamp, pid, tid, (int32_t)arg0, (int32_t)arg1);
}

carrick*:::signal-inject
/(pid == $target || progenyof($target)) && (int32_t)arg0 != 0/
{
    injects++;
    signal_events++;
    printf("HVPATCHKSIG1|inject|timestamp=%llu|host_pid=%d|host_tid=%d|signum=%d|saved_pc=0x%llx|new_sp=0x%llx|handler=0x%llx\n",
        timestamp, pid, tid, (int32_t)arg0, (uint64_t)arg1,
        (uint64_t)arg2, (uint64_t)arg3);
}

carrick*:::kick-in_kernel
/(pid == $target || progenyof($target))/
{
    kernel_kicks++;
    printf("HVPATCHKSIG1|kick-in-kernel|timestamp=%llu|host_pid=%d|host_tid=%d|pc=0x%llx|el=%u\n",
        timestamp, pid, tid, (uint64_t)arg0, (uint32_t)arg1);
}

carrick*:::vcpu-kick
/(pid == $target || progenyof($target))/
{
    vcpu_kicks++;
    @vcpu_kick_outcomes[(int32_t)arg1, (int32_t)arg2] = count();
}

dtrace:::ERROR
{
    errors++;
}

profile:::tick-45sec
{
    bounded = 1;
    exit(0);
}

dtrace:::END
{
    printa("HVPATCHKSIG1|vcpu-kick-count|valid=%d|rc=%d|count=%@d\n",
        @vcpu_kick_outcomes);
    printf("HVPATCHKSIG1|summary|publishes=%d|delivers=%d|injects=%d|signal_events=%d|kernel_kicks=%d|vcpu_kicks=%d|bounded=%d|errors=%d\n",
        publishes, delivers, injects, signal_events, kernel_kicks, vcpu_kicks,
        bounded, errors);
    exit(errors != 0 || signal_events == 0 || vcpu_kicks == 0 ? 1 : 0);
}
