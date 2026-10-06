#pragma D option quiet
#pragma D option strsize=256

/*
 * WHICH HOST IPC COPY LOWERS OWNER MEMORY CONTENTION TO A GUEST ERROR?
 *
 * (a) Records guest-memory validation failures and owner-copy preparation,
 *     with host stacks at failures. No guest bytes are captured.
 * (b) Source ABI: guest-internal-write-fault(va,len,phase,error-string),
 *     hvpatch-el1-host-write-prepare(va,len,phase,detail), and
 *     hvpatch-el1-host-read-progress(va,len,offset,class,detail).
 *     hvpatch-guest-fault(ESR,ELR,FAR,guest-pid,guest-tid) and
 *     hvpatch-fault-terminal(FAR,signal,si-code,guest-tid) distinguish
 *     the original guest fault from later core-publication copy refusals.
 *     hvpatch-syscall-service-begin captures guest PID/TID on the servicing
 *     host thread; syscall-return reports NR, name, return value and errno.
 *     Only guest EFAULT returns are printed, with that captured identity.
 *     Validation phases and preparation outcomes come from the exact
 *     carrick-observability provider. Live firing must be checked per capture.
 * (c) Failure-only stacks perturb execution; this is mechanism evidence,
 *     never timing or acceptance evidence. The 180-second diagnostic bound
 *     includes signed-launcher fixture verification and signing.
 *
 * Keep the tracer and signed witness run IDs distinct: the signed runner's
 * scoped EXIT reap can kill a tracer sharing its run ID, before END prints.
 * The ed2b48ac6 exit-group capture fired phase 4/detail 1 for a 16-byte
 * successful-sleep copyout; its preserved stack named continuation folding.
 * The 7ef330f81 reader capture's first read refusals were already in core
 * capture. They do not establish the cause of the earlier guest crash.
 * Its fault capture then fired first-touch-refused site 1 and terminal
 * SIGSEGV for a thread stack: admitted owner MM cannot enter host sparse
 * publication. The added EFAULT-return arm remains source-qualified only;
 * its first capture exhausted the diagnostic bound during build/signing.
 *
 * CARRICK_RUN_ID=<trace-id> carrick trace -s scripts/dtrace/el1-ipc-host-copy.d
 *   -o <capture> -- --external env CARRICK_RUN_ID=<test-id>
 *   ./scripts/test-signed.sh carrick-embed <test> --exact --nocapture
 */

carrick*:::guest-internal-write-fault
/pid == $target || progenyof($target)/
{
    events++;
    printf("IPCCOPY1|ns=%llu|pid=%d|tid=%d|validation|va=0x%llx|len=%llu|phase=%u|error=%s\n",
        timestamp, pid, tid, (uint64_t)arg0, (uint64_t)arg1,
        (uint32_t)arg2, copyinstr(arg3));
    ustack(20);
}

carrick*:::hvpatch-el1-host-write-prepare
/(pid == $target || progenyof($target)) && arg2 != 0 && arg2 != 3/
{
    events++;
    printf("IPCCOPY1|ns=%llu|pid=%d|tid=%d|prepare|va=0x%llx|len=%llu|phase=%u|detail=%llu\n",
        timestamp, pid, tid, (uint64_t)arg0, (uint64_t)arg1,
        (uint32_t)arg2, (uint64_t)arg3);
    ustack(20);
}

carrick*:::hvpatch-el1-host-read-progress
/(pid == $target || progenyof($target)) && arg3 >= 2/
{
    events++;
    printf("IPCCOPY1|ns=%llu|pid=%d|tid=%d|read|va=0x%llx|len=%llu|offset=%llu|class=%u|detail=%llu\n",
        timestamp, pid, tid, (uint64_t)arg0, (uint64_t)arg1,
        (uint64_t)arg2, (uint32_t)arg3, (uint64_t)arg4);
    ustack(20);
}

tick-1s { seconds++; }
tick-1s /seconds >= 180/ { exit(events == 0 ? 1 : 0); }
END { printf("IPCCOPY1|events=%d\n", events); }

carrick*:::hvpatch-guest-fault
/pid == $target || progenyof($target)/
{
    events++;
    printf("IPCCOPY1|ns=%llu|pid=%d|tid=%d|guest-fault|esr=0x%llx|elr=0x%llx|far=0x%llx|guest-pid=%d|guest-tid=%d\n",
        timestamp, pid, tid, (uint64_t)arg0, (uint64_t)arg1,
        (uint64_t)arg2, (int32_t)arg3, (int32_t)arg4);
}

carrick*:::hvpatch-fault-terminal
/pid == $target || progenyof($target)/
{
    events++;
    printf("IPCCOPY1|ns=%llu|pid=%d|tid=%d|fault-terminal|far=0x%llx|signal=%d|si-code=%d|guest-tid=%d\n",
        timestamp, pid, tid, (uint64_t)arg0, (int32_t)arg1,
        (int32_t)arg2, (int32_t)arg3);
    ustack(20);
}

carrick*:::hvpatch-first-touch-refused
/pid == $target || progenyof($target)/
{
    events++;
    printf("IPCCOPY1|ns=%llu|pid=%d|tid=%d|first-touch-refused|page=0x%llx|access=%u|site=%u|error=%s\n",
        timestamp, pid, tid, (uint64_t)arg0, (uint32_t)arg1,
        (uint32_t)arg2, copyinstr(arg3));
}

carrick*:::hvpatch-syscall-service-begin
/pid == $target || progenyof($target)/
{
    self->guest_pid = (int32_t)arg0;
    self->guest_tid = (int32_t)arg1;
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (int64_t)arg2 == -14/
{
    events++;
    printf("IPCCOPY1|ns=%llu|pid=%d|tid=%d|efault-return|guest-pid=%d|guest-tid=%d|nr=%llu|name=%s\n",
        timestamp, pid, tid, self->guest_pid, self->guest_tid,
        (uint64_t)arg0, copyinstr(arg1));
}
