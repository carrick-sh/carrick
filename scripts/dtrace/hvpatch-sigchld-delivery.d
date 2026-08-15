#!/usr/sbin/dtrace -qs
/*
 * Attribute HVPatch SIGCHLD delivery from guest fork through handler injection.
 *
 * WHAT: records the guest clone/wait boundary and the three typed signal
 * lifecycle receipts: publication to the parent Linux tid, delivery-cycle
 * drain by that tid, and construction of the guest handler frame.  A failed
 * sigchld probe can therefore distinguish child-exit observation/publication
 * loss from a lost vCPU kick/drain or a post-drain disposition/injection loss.
 *
 * ABI (qualified live on macOS/arm64, 2026-08-15):
 * - syscall-entry: u64 nr, char *name, pointer to six contiguous u64 args.
 * - syscall-return: u64 nr, char *name, i64 retval, i32 Linux errno.
 * - signal-publish: i32 target Linux tid, i32 Linux signum, i32 kind
 *   (1 thread-directed, 0 process-directed).
 * - signal-deliver: i32 delivering Linux tid, i32 drained Linux signum
 *   (zero means no deliverable signal).
 * - signal-inject: i32 Linux signum, u64 saved PC, u64 new SP, u64 handler.
 * - vcpu-kick: u64 vCPU handle, i32 handle-valid flag, i32 raw
 *   hv_vcpus_exit return code.
 * AArch64 syscall numbers selected here are rt_sigaction=134, clone=220, and
 * wait4=260.
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

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
 (arg0 == 134 || arg0 == 220 || arg0 == 260)/
{
    this->a = (uint64_t *)copyin(arg2, 48);
    printf("HVPATCHSIGCHLD1|entry|timestamp=%llu|host_pid=%d|host_tid=%d|nr=%llu|name=%s|a0=0x%llx|a1=0x%llx|a2=0x%llx|a3=0x%llx\n",
        timestamp, pid, tid, (uint64_t)arg0, copyinstr(arg1),
        this->a[0], this->a[1], this->a[2], this->a[3]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
 (arg0 == 134 || arg0 == 220 || arg0 == 260)/
{
    syscall_returns++;
    arg0 == 220 ? clone_returns++ : 0;
    printf("HVPATCHSIGCHLD1|return|timestamp=%llu|host_pid=%d|host_tid=%d|nr=%llu|name=%s|retval=%lld|errno=%d\n",
        timestamp, pid, tid, (uint64_t)arg0, copyinstr(arg1),
        (int64_t)arg2, (int)arg3);
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
    printf("HVPATCHSIGCHLD1|summary|syscall_returns=%d|clone_returns=%d|publishes=%d|delivers=%d|injects=%d|bounded=%d|errors=%d\n",
        syscall_returns, clone_returns, sigchld_publishes, sigchld_delivers,
        sigchld_injects, bounded, errors);
    printf("HVPATCHSIGCHLD1|kick-summary|kicks=%d|invalid=%d|failed=%d|last_timestamp=%llu|last_vcpu=%llu|last_rc=%d\n",
        kicks, invalid_kicks, failed_kicks, (uint64_t)last_kick_timestamp,
        (uint64_t)last_kick_vcpu, last_kick_rc);
    exit(clone_returns == 0 || bounded != 0 || errors != 0 ? 1 : 0);
}
