/*
 * vfork-smash-signal-injections.d — was a guest stack-canary smash preceded by
 * a carrick sigframe injection (and at what SP), or by nothing signal-shaped?
 *
 * Question: gate-load runs of vfork/clone probes die with glibc/musl
 * "*** stack smashing detected ***" (canary mismatch at function epilogue)
 * while green standalone. Discriminate the two candidate mechanisms:
 *   (a) carrick writes an rt_sigframe at a stale/wrong SP into the shared mm
 *       -> a signal-inject event with new_sp inside the victim's live stack
 *          shortly before the abort;
 *   (b) memory/COW/exec page-ownership corruption -> NO signal-inject near
 *       the abort.
 *
 * Provider ABI facts (qualified from carrick-observability/probes.rs and the
 * repo's live-qualified macOS/arm64 scripts at this repo HEAD):
 *   carrick*:::signal-inject  arg0=signum arg1=saved_pc arg2=new_sp arg3=handler
 *   carrick*:::signal-restore arg0=saved_pc arg1=sp arg2=magic
 *   carrick*:::hvpatch-syscall-service-begin
 *     arg0=Linux pid arg1=Linux tid arg2=ASID arg3=Linux syscall number.
 *   carrick*:::hvpatch-syscall-args
 *     arg0=syscall number arg1..arg4=guest args 0..3; it fires immediately
 *     after an enabled service-begin on the same host thread.  These two probes
 *     are the authoritative logical-identity join for the syscall-entry,
 *     syscall-return, clone, exec, wait, and rt_sigprocmask rows below.
 *   carrick*:::hvpatch-syscall-service
 *     repeats pid/tid/ASID/number in arg0..arg3 and carries dispatch-slice
 *     duration_ns in arg4.  A blocking syscall may have multiple slices.
 *   carrick*:::hvpatch-syscall-service-clear repeats pid/tid/ASID/number and
 *     is the terminal boundary for that host-thread service window.
 *   carrick*:::syscall-entry  arg0=Linux nr arg1=name arg2=&args[6]
 *     (arg2 is a HOST pointer to six u64s, so copyin(arg2,48) is valid;
 *      guest buffer pointers inside that array remain guest VAs)
 *   carrick*:::syscall-return arg0=Linux nr arg1=name arg2=ret arg3=errno
 *   carrick*:::fork-post      arg0=child host pid
 *   carrick*:::hvpatch-guest-lifecycle-identity
 *     arg0=Linux pid arg1=TaskSerial arg2=parent TaskSerial arg3=MmId and
 *     fires immediately before hvpatch-guest-lifecycle on the same host thread.
 *   carrick*:::hvpatch-guest-lifecycle
 *     arg0=phase arg1=Linux pid arg2=Linux ppid arg3=Linux tid arg4=ASID;
 *     phases are 0=root, 1=fork, 2=exec, 3=thread-start, 4=thread-exit,
 *     5=process-exit, 6=exec-begin.  hvpatch-guest-exit carries pid, tid,
 *     ASID, and wait status for phase 5.
 *   carrick*:::hvpatch-thread-terminal
 *     arg0=Linux pid arg1=Linux tid arg2=ThreadRegistry tid arg3=reason
 *     arg4=detail; reasons are 0=guest thread exit, 1=exec registry gone at
 *     loop top, 2=exec registry gone after a blocking wait, 3=vfork-parent
 *     terminal cancellation, 4=process-terminal loser.
 *   carrick*:::mn-clone-outcome arg0=invoking/reserved Linux tid arg1=phase
 *     arg2=Linux errno.  Stable phases 0..14 are admission-closed,
 *     admission-cancelled, reserved, host-thread-started,
 *     child-cancelled-before-slot, admitted, child-cancelled-before-
 *     materialize, materialized, child-cancelled-after-materialize,
 *     materialization-failed, host-thread-spawn-failed, start-cancelled,
 *     child-published, parent-resumed/started, and guest-retval-completed.
 *   carrick*:::hvpatch-exec-runtime-stage
 *     arg0=phase (0=proc-state, 1=close-on-exec, 2=sibling-drain,
 *     3=topology-lock, 4=engine-replacement, 5=publication), arg1=elapsed_ns,
 *     arg2=image region count, arg3=mapped bytes.  This probe deliberately has
 *     NO logical identity.  Its only valid join is host pid/tid plus timestamp;
 *     do not copy a possibly reassigned vCPU thread's last syscall identity
 *     onto it.  In particular, compare parent service-begin timestamps against
 *     the child's exec service-begin and phase-5 publication timestamp.
 *
 * Output protocol: VFORKSMASH1, version 1.  Every row is one pipe-delimited,
 * machine-greppable record.  `identity_source=service` is exact for an active
 * service window; signal/fork-post rows say `last_service` because those probes
 * do not themselves publish logical identity and the value is only a causal
 * breadcrumb on the same host thread.
 *
 * Perturbation: per-event printf on the selected syscall service boundaries,
 * lifecycle/clone/terminal events, exec stages, and signal events; moderate to
 * high on clone-heavy load. A vanished repro under this script is itself a
 * finding (timing), and captures are diagnostic rather than performance data.
 *
 * Usage (traced lane; load lanes run separately):
 *   carrick trace --script scripts/dtrace/vfork-smash-signal-injections.d \
 *     --trace-out <out> -- run --raw --fs host ubuntu:24.04 /bin/sh -c '...'
 */
#pragma D option quiet
#pragma D option strsize=512

dtrace:::BEGIN
{
    printf("VFORKSMASH1|header|version=1\n");
}

carrick*:::hvpatch-syscall-service-begin
/pid == $target || progenyof($target)/
{
    /* A signal probe may run outside a service window.  Retain the latest
     * identity observed on this host thread, but label it non-authoritative. */
    self->last_pid = (int32_t)arg0;
    self->last_tid = (int32_t)arg1;
    self->last_asid = (uint32_t)arg2;
    self->last_nr = (uint64_t)arg3;
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) &&
 (arg3 == 58 || arg3 == 64 || arg3 == 93 || arg3 == 94 || arg3 == 135 ||
  arg3 == 220 || arg3 == 221 || arg3 == 260)/
{
    self->service_pid = (int32_t)arg0;
    self->service_tid = (int32_t)arg1;
    self->service_asid = (uint32_t)arg2;
    self->service_nr = (uint64_t)arg3;
    printf("VFORKSMASH1|service-begin|ts=%llu|host_pid=%d|host_tid=%d|linux_pid=%d|linux_tid=%d|asid=%u|nr=%llu\n",
        timestamp, pid, tid, self->service_pid, self->service_tid,
        self->service_asid, self->service_nr);
}

carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target)) &&
 self->service_nr != 0 && (uint64_t)arg0 == self->service_nr/
{
    printf("VFORKSMASH1|service-args|ts=%llu|host_pid=%d|host_tid=%d|linux_pid=%d|linux_tid=%d|asid=%u|nr=%llu|a0=0x%llx|a1=0x%llx|a2=0x%llx|a3=0x%llx\n",
        timestamp, pid, tid, self->service_pid, self->service_tid,
        self->service_asid, self->service_nr, (uint64_t)arg1,
        (uint64_t)arg2, (uint64_t)arg3, (uint64_t)arg4);
}

carrick*:::hvpatch-syscall-service
/(pid == $target || progenyof($target)) &&
 (arg3 == 58 || arg3 == 64 || arg3 == 93 || arg3 == 94 || arg3 == 135 ||
  arg3 == 220 || arg3 == 221 || arg3 == 260)/
{
    printf("VFORKSMASH1|service-end|ts=%llu|host_pid=%d|host_tid=%d|linux_pid=%d|linux_tid=%d|asid=%u|nr=%llu|duration_ns=%llu\n",
        timestamp, pid, tid, (int32_t)arg0, (int32_t)arg1,
        (uint32_t)arg2, (uint64_t)arg3, (uint64_t)arg4);
}

carrick*:::hvpatch-syscall-service-clear
/(pid == $target || progenyof($target)) &&
 (arg3 == 58 || arg3 == 64 || arg3 == 93 || arg3 == 94 || arg3 == 135 ||
  arg3 == 220 || arg3 == 221 || arg3 == 260)/
{
    printf("VFORKSMASH1|service-clear|ts=%llu|host_pid=%d|host_tid=%d|linux_pid=%d|linux_tid=%d|asid=%u|nr=%llu\n",
        timestamp, pid, tid, (int32_t)arg0, (int32_t)arg1,
        (uint32_t)arg2, (uint64_t)arg3);
    self->service_pid = 0;
    self->service_tid = 0;
    self->service_asid = 0;
    self->service_nr = 0;
}

carrick*:::signal-inject
/pid == $target || progenyof($target)/
{
    printf("VFORKSMASH1|inject|ts=%llu|host_pid=%d|host_tid=%d|linux_pid=%d|linux_tid=%d|asid=%u|last_nr=%llu|identity_source=last_service|signum=%d|saved_pc=0x%llx|new_sp=0x%llx|handler=0x%llx\n",
        timestamp, pid, tid, self->last_pid, self->last_tid, self->last_asid,
        self->last_nr, (int32_t)arg0, (uint64_t)arg1, (uint64_t)arg2,
        (uint64_t)arg3);
}

carrick*:::signal-restore
/pid == $target || progenyof($target)/
{
    printf("VFORKSMASH1|restore|ts=%llu|host_pid=%d|host_tid=%d|linux_pid=%d|linux_tid=%d|asid=%u|last_nr=%llu|identity_source=last_service|saved_pc=0x%llx|sp=0x%llx|magic=0x%llx\n",
        timestamp, pid, tid, self->last_pid, self->last_tid, self->last_asid,
        self->last_nr, (uint64_t)arg0, (uint64_t)arg1, (uint64_t)arg2);
}

/* vfork(58), clone(220), execve(221), wait4(260), exit(93), exit_group(94), write(64) */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
 (arg0 == 58 || arg0 == 135 || arg0 == 220 || arg0 == 221 || arg0 == 260 ||
  arg0 == 93 || arg0 == 94)/
{
    printf("VFORKSMASH1|entry|ts=%llu|host_pid=%d|host_tid=%d|linux_pid=%d|linux_tid=%d|asid=%u|nr=%llu|identity_source=service|identity_match=%d|name=%s\n",
        timestamp, pid, tid, self->service_pid, self->service_tid,
        self->service_asid, (uint64_t)arg0,
        self->service_nr == (uint64_t)arg0, copyinstr(arg1));
}

/* clone: flags, child_stack, parent_tid, exit_signal/tls, child_tid. */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 220/
{
    this->a = (uint64_t *)copyin(arg2, 48);
    printf("VFORKSMASH1|clone|ts=%llu|host_pid=%d|host_tid=%d|linux_pid=%d|linux_tid=%d|asid=%u|identity_source=service|identity_match=%d|flags=0x%llx|child_stack=0x%llx|parent_tid=0x%llx|a3=0x%llx|child_tid=0x%llx\n",
        timestamp, pid, tid, self->service_pid, self->service_tid,
        self->service_asid, self->service_nr == 220, this->a[0],
        this->a[1], this->a[2], this->a[3], this->a[4]);
}

/* rt_sigprocmask(135): how, new-set guest VA, old-set guest VA, size. */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 135/
{
    this->a = (uint64_t *)copyin(arg2, 48);
    printf("VFORKSMASH1|sigmask|ts=%llu|host_pid=%d|host_tid=%d|linux_pid=%d|linux_tid=%d|asid=%u|identity_source=service|identity_match=%d|how=%d|nset=0x%llx|oset=0x%llx|size=%d\n",
        timestamp, pid, tid, self->service_pid, self->service_tid,
        self->service_asid, self->service_nr == 135, (int32_t)this->a[0],
        this->a[1], this->a[2], (int32_t)this->a[3]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
 (arg0 == 58 || arg0 == 135 || arg0 == 220 || arg0 == 221 || arg0 == 260)/
{
    printf("VFORKSMASH1|return|ts=%llu|host_pid=%d|host_tid=%d|linux_pid=%d|linux_tid=%d|asid=%u|nr=%llu|identity_source=service|identity_match=%d|name=%s|retval=%lld|errno=%d\n",
        timestamp, pid, tid, self->service_pid, self->service_tid,
        self->service_asid, (uint64_t)arg0,
        self->service_nr == (uint64_t)arg0, copyinstr(arg1),
        (int64_t)arg2, (int32_t)arg3);
}

/* the abort path: the guest writes the smash message then raises */
carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 64/
{
    printf("VFORKSMASH1|write-return|ts=%llu|host_pid=%d|host_tid=%d|linux_pid=%d|linux_tid=%d|asid=%u|identity_source=service|identity_match=%d|retval=%lld\n",
        timestamp, pid, tid, self->service_pid, self->service_tid,
        self->service_asid, self->service_nr == 64, (int64_t)arg2);
}

carrick*:::fork-post
/pid == $target || progenyof($target)/
{
    printf("VFORKSMASH1|fork-post|ts=%llu|host_pid=%d|host_tid=%d|linux_pid=%d|linux_tid=%d|asid=%u|last_nr=%llu|identity_source=last_service|child_host_pid=%d\n",
        timestamp, pid, tid, self->last_pid, self->last_tid, self->last_asid,
        self->last_nr, (int32_t)arg0);
}

carrick*:::hvpatch-guest-lifecycle-identity
/pid == $target || progenyof($target)/
{
    self->lifecycle_pid = (int32_t)arg0;
    self->task_serial = (uint64_t)arg1;
    self->parent_serial = (uint64_t)arg2;
    self->mm = (uint64_t)arg3;
    printf("VFORKSMASH1|lifecycle-identity|ts=%llu|host_pid=%d|host_tid=%d|linux_pid=%d|task_serial=%llu|parent_serial=%llu|mm=%llu\n",
        timestamp, pid, tid, self->lifecycle_pid, self->task_serial,
        self->parent_serial, self->mm);
}

carrick*:::hvpatch-guest-lifecycle
/pid == $target || progenyof($target)/
{
    printf("VFORKSMASH1|lifecycle|ts=%llu|host_pid=%d|host_tid=%d|phase=%u|linux_pid=%d|linux_ppid=%d|linux_tid=%d|asid=%u|task_serial=%llu|parent_serial=%llu|mm=%llu|identity_match=%d\n",
        timestamp, pid, tid, (uint32_t)arg0, (int32_t)arg1,
        (int32_t)arg2, (int32_t)arg3, (uint32_t)arg4,
        self->task_serial, self->parent_serial, self->mm,
        self->lifecycle_pid == (int32_t)arg1);
    self->lifecycle_pid = 0;
    self->task_serial = 0;
    self->parent_serial = 0;
    self->mm = 0;
}

carrick*:::hvpatch-guest-exit
/pid == $target || progenyof($target)/
{
    printf("VFORKSMASH1|guest-exit|ts=%llu|host_pid=%d|host_tid=%d|linux_pid=%d|linux_tid=%d|asid=%u|status=%lld\n",
        timestamp, pid, tid, (int32_t)arg0, (int32_t)arg1,
        (uint32_t)arg2, (int64_t)arg3);
}

carrick*:::hvpatch-thread-terminal
/pid == $target || progenyof($target)/
{
    printf("VFORKSMASH1|thread-terminal|ts=%llu|host_pid=%d|host_tid=%d|linux_pid=%d|linux_tid=%d|registry_tid=%d|reason=%u|detail=%d\n",
        timestamp, pid, tid, (int32_t)arg0, (int32_t)arg1,
        (int32_t)arg2, (uint32_t)arg3, (int32_t)arg4);
}

carrick*:::mn-clone-outcome
/pid == $target || progenyof($target)/
{
    printf("VFORKSMASH1|clone-outcome|ts=%llu|host_pid=%d|host_tid=%d|source_pid=%d|source_tid=%d|source_asid=%u|source_nr=%llu|identity_source=active_service|linux_tid=%d|phase=%u|errno=%d\n",
        timestamp, pid, tid, self->service_pid, self->service_tid,
        self->service_asid, self->service_nr, (int32_t)arg0,
        (uint32_t)arg1, (int32_t)arg2);
}

/* This provider has no logical identity: join only on host pid/tid/timestamp. */
carrick*:::hvpatch-exec-runtime-stage
/pid == $target || progenyof($target)/
{
    printf("VFORKSMASH1|exec-runtime-stage|ts=%llu|host_pid=%d|host_tid=%d|identity_source=host_thread_timestamp_only|phase=%u|elapsed_ns=%llu|region_count=%llu|mapped_bytes=%llu\n",
        timestamp, pid, tid, (uint32_t)arg0, (uint64_t)arg1,
        (uint64_t)arg2, (uint64_t)arg3);
}

tick-1s { secs++; }
tick-1s /secs >= 90/ { exit(0); }
