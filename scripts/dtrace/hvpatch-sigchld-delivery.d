#!/usr/sbin/dtrace -qs
/*
 * Attribute HVPatch SIGCHLD delivery from guest fork through handler injection.
 *
 * WHAT: records the guest clone/wait boundary and the three typed signal
 * lifecycle receipts: publication to the parent Linux tid, delivery-cycle
 * drain by that tid, and construction of the guest handler frame.  It also
 * records Go's pidfd path (pidfd_open, epoll/ppoll readiness, waitid(P_PIDFD),
 * then terminal wait4) and distinguishes exit(2) from exit_group(2), so a
 * durable zombie cannot be misattributed to SIGCHLD when the actual missed
 * edge is pidfd readiness, waitid, or thread-group teardown.  A failed sigchld
 * probe can therefore distinguish child-exit observation/publication loss
 * from a lost vCPU kick/drain, a pidfd wait loss, a single-thread exit, or a
 * post-drain disposition/injection loss.
 *
 * ABI (qualified live on macOS/arm64, 2026-08-15):
 * - hvpatch-syscall-service-begin: i32 Linux pid, i32 Linux tid, u32 ASID,
 *   u64 syscall number.
 * - hvpatch-syscall-args: u64 syscall number, then guest args 0..3. This
 *   companion fires immediately after service-begin on the same host thread.
 * - hvpatch-syscall-service: the same pid/tid/ASID/number plus dispatch-slice
 *   duration ns. A blocking syscall can have many completed slices before it
 *   returns to Linux; the END aggregation preserves that fact without printing
 *   a misleading synthetic retval for every redispatch.
 * - signal-publish: i32 target Linux tid, i32 Linux signum, i32 kind
 *   (1 thread-directed, 0 process-directed).
 * - signal-deliver: i32 delivering Linux tid, i32 drained Linux signum
 *   (zero means no deliverable signal).
 * - signal-inject: i32 Linux signum, u64 saved PC, u64 new SP, u64 handler.
 * - vcpu-kick: u64 vCPU handle, i32 handle-valid flag, i32 raw
 *   hv_vcpus_exit return code.
 * AArch64 syscall numbers selected here are epoll_pwait=22, ppoll=73,
 * exit=93, exit_group=94, waitid=95, rt_sigaction=134, clone=220, wait4=260,
 * pidfd_open=434, and epoll_pwait2=441.
 *
 * PERTURBATION: LOW.  Only three setup/lifecycle syscalls and SIGCHLD-specific
 * signal events print; empty delivery cycles are ignored.  This is diagnostic,
 * never timing/performance evidence.  Zero clone returns or DTrace errors make
 * the capture fail closed; signal counts may legitimately be zero because that
 * is the failure shape this script is designed to preserve.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    syscall_returns = 0;
    clone_returns = 0;
    sigchld_publishes = 0;
    sigchld_delivers = 0;
    sigchld_injects = 0;
    kicks = 0;
    invalid_kicks = 0;
    failed_kicks = 0;
    last_kick_timestamp = (uint64_t)0;
    last_kick_vcpu = (uint64_t)0;
    last_kick_rc = 0;
    errors = 0;
    bounded = 0;
}

carrick*:::kick-in-kernel
/(pid == $target || progenyof($target))/
{
    printf("HVPATCHSIGCHLD1|kick-in-kernel|timestamp=%llu|host_pid=%d|host_tid=%d|pc=0x%llx|el=%u\n",
        timestamp, pid, tid, (uint64_t)arg0, (uint32_t)arg1);
}

carrick*:::vcpu-kick
/(pid == $target || progenyof($target))/
{
    kicks++;
    (int32_t)arg1 == 0 ? invalid_kicks++ : 0;
    (int32_t)arg2 != 0 ? failed_kicks++ : 0;
    last_kick_timestamp = timestamp;
    last_kick_vcpu = (uint64_t)arg0;
    last_kick_rc = (int32_t)arg2;
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) &&
 (arg3 == 22 || arg3 == 73 || arg3 == 93 || arg3 == 94 || arg3 == 95 ||
  arg3 == 134 || arg3 == 220 || arg3 == 260 || arg3 == 434 || arg3 == 441)/
{
    self->guest_pid = (int32_t)arg0;
    self->guest_tid = (int32_t)arg1;
    self->guest_asid = (uint32_t)arg2;
    self->guest_nr = (uint64_t)arg3;
}

carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target)) &&
 self->guest_nr == (uint64_t)arg0/
{
    self->a0 = (uint64_t)arg1;
    self->a1 = (uint64_t)arg2;
    self->a2 = (uint64_t)arg3;
    self->a3 = (uint64_t)arg4;
    @service_calls[self->guest_pid, self->guest_tid, self->guest_nr,
        self->a0, self->a1] = count();
    seen_wait[self->guest_pid, self->guest_tid, self->guest_nr,
        self->a0, self->a1]++;
    /* Print lifecycle syscalls and only the first slice of each wait tuple. */
    self->emit = self->guest_nr == 93 || self->guest_nr == 94 ||
        (self->guest_nr == 134 && self->a0 == 17) ||
        self->guest_nr == 220 || self->guest_nr == 434 ||
        ((self->guest_nr == 22 || self->guest_nr == 73 ||
          self->guest_nr == 95 || self->guest_nr == 260 ||
          self->guest_nr == 441) &&
         seen_wait[self->guest_pid, self->guest_tid, self->guest_nr,
             self->a0, self->a1] == 1);
}

carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target)) &&
 self->guest_nr == (uint64_t)arg0 && self->emit/
{
    printf("HVPATCHSIGCHLD1|service-begin|timestamp=%llu|host_pid=%d|host_tid=%d|guest_pid=%d|guest_tid=%d|asid=%u|nr=%llu|a0=0x%llx|a1=0x%llx|a2=0x%llx|a3=0x%llx\n",
        timestamp, pid, tid, self->guest_pid, self->guest_tid,
        self->guest_asid, self->guest_nr, self->a0, self->a1,
        self->a2, self->a3);
}

carrick*:::hvpatch-syscall-service
/(pid == $target || progenyof($target)) &&
 self->guest_nr == (uint64_t)arg3/
{
    syscall_returns++;
    self->guest_nr == 220 ? clone_returns++ : 0;
    @service_completions[(int32_t)arg0, (int32_t)arg1, (uint64_t)arg3] = count();
    @service_duration_ns[(int32_t)arg0, (int32_t)arg1, (uint64_t)arg3] = sum((uint64_t)arg4);
}

carrick*:::hvpatch-syscall-service
/(pid == $target || progenyof($target)) &&
 self->guest_nr == (uint64_t)arg3 && self->emit/
{
    printf("HVPATCHSIGCHLD1|service-end|timestamp=%llu|host_pid=%d|host_tid=%d|guest_pid=%d|guest_tid=%d|asid=%u|nr=%llu|duration_ns=%llu\n",
        timestamp, pid, tid, (int32_t)arg0, (int32_t)arg1,
        (uint32_t)arg2, (uint64_t)arg3, (uint64_t)arg4);
}

carrick*:::hvpatch-syscall-service-clear
/(pid == $target || progenyof($target)) && self->guest_nr != 0/
{
    self->guest_pid = 0;
    self->guest_tid = 0;
    self->guest_asid = 0;
    self->guest_nr = 0;
    self->a0 = 0;
    self->a1 = 0;
    self->a2 = 0;
    self->a3 = 0;
    self->emit = 0;
}

carrick*:::signal-publish
/(pid == $target || progenyof($target)) && (int32_t)arg1 == 17/
{
    sigchld_publishes++;
    printf("HVPATCHSIGCHLD1|publish|timestamp=%llu|host_pid=%d|host_tid=%d|target_tid=%d|signum=%d|kind=%d\n",
        timestamp, pid, tid, (int32_t)arg0, (int32_t)arg1, (int32_t)arg2);
}

carrick*:::signal-deliver
/(pid == $target || progenyof($target)) && (int32_t)arg1 == 17/
{
    sigchld_delivers++;
    printf("HVPATCHSIGCHLD1|deliver|timestamp=%llu|host_pid=%d|host_tid=%d|linux_tid=%d|signum=%d\n",
        timestamp, pid, tid, (int32_t)arg0, (int32_t)arg1);
}

carrick*:::signal-inject
/(pid == $target || progenyof($target)) && (int32_t)arg0 == 17/
{
    sigchld_injects++;
    printf("HVPATCHSIGCHLD1|inject|timestamp=%llu|host_pid=%d|host_tid=%d|signum=%d|saved_pc=0x%llx|new_sp=0x%llx|handler=0x%llx\n",
        timestamp, pid, tid, (int32_t)arg0, (uint64_t)arg1,
        (uint64_t)arg2, (uint64_t)arg3);
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
/timestamp - started > 90 * 1000000000/
{
    bounded = 1;
    exit(0);
}

dtrace:::END
{
    printa("HVPATCHSIGCHLD1|service-call-count|guest_pid=%d|guest_tid=%d|nr=%llu|a0=0x%llx|a1=0x%llx|count=%@d\n",
        @service_calls);
    printa("HVPATCHSIGCHLD1|service-completion-count|guest_pid=%d|guest_tid=%d|nr=%llu|count=%@d\n",
        @service_completions);
    printa("HVPATCHSIGCHLD1|service-duration-ns|guest_pid=%d|guest_tid=%d|nr=%llu|sum=%@d\n",
        @service_duration_ns);
    printf("HVPATCHSIGCHLD1|summary|syscall_returns=%d|clone_returns=%d|publishes=%d|delivers=%d|injects=%d|bounded=%d|errors=%d\n",
        syscall_returns, clone_returns, sigchld_publishes, sigchld_delivers,
        sigchld_injects, bounded, errors);
    printf("HVPATCHSIGCHLD1|kick-summary|kicks=%d|invalid=%d|failed=%d|last_timestamp=%llu|last_vcpu=%llu|last_rc=%d\n",
        kicks, invalid_kicks, failed_kicks, (uint64_t)last_kick_timestamp,
        (uint64_t)last_kick_vcpu, last_kick_rc);
    exit(clone_returns == 0 || bounded != 0 || errors != 0 ? 1 : 0);
}
