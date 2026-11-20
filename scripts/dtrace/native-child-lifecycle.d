/*
 * native-child-lifecycle.d — ordered stream of ring-owned native child transitions
 *
 * WHAT: traces every native child fork, exec, exit (including terminal run
 * failures, EntryBindingFatal codes such as NativeServiceQuarantined=36, and
 * carrier fatals before abort), zombie publication, waiting-parent wake, and
 * wait4/waitid reap inside one VM carrier (#2620). Unlike host-only
 * `hvpatch-guest-lifecycle`, which fires only for root/host-spawned tasks and
 * shows zero events for ring-owned fork children, these probes mirror the
 * neutral `NativeProcessRuntime` lifecycle transitions drained at host
 * boundaries and pre-abort sinks.
 *
 * ABI (scalar-arg convention, <= 5 scalar args per probe to stay within the
 * macOS/arm64 5-arg USDT register window, defined in
 * crates/carrick-observability/src/probes.rs):
 * - native-child-fork: arg0 u64 parent TaskId, arg1 u64 parent TaskSerial,
 *   arg2 u64 child TaskId, arg3 u64 child TaskSerial, arg4 u64 packed flags
 *   (bits 0..7 exit_signal, bit 8 vfork, bit 9 settid, bit 10 cleartid).
 * - native-child-exec: arg0 u64 task TaskId, arg1 u64 task TaskSerial,
 *   arg2 u32 succeeded (1=ok, 0=refused), arg3 i32 detail (0=ok, >0=errno,
 *   -1=past_no_return).
 * - native-child-exit: arg0 u64 task TaskId, arg1 u64 task TaskSerial,
 *   arg2 u32 reason_class (1=exited, 2=signaled, 3=run_failure,
 *   4=entry_fatal, 5=carrier_fatal), arg3 u32 reason_code, arg4 u32 wstatus.
 * - native-child-zombie: arg0 u64 child TaskId, arg1 u64 child TaskSerial,
 *   arg2 u64 parent TaskId, arg3 u64 parent TaskSerial.
 * - native-child-wake: arg0 u64 parent TaskId, arg1 u64 parent TaskSerial,
 *   arg2 u32 wake_reason (1=child_exit, 2=signal, 3=none), arg3 u32 woken.
 * - native-child-reap: arg0 u64 caller TaskId, arg1 u64 caller TaskSerial,
 *   arg2 u64 child TaskId, arg3 u64 child TaskSerial, arg4 u32 wstatus.
 *
 * PERTURBATION: LOW — fires only on process-level fork/exec/exit/wait
 * transitions (never per-syscall or per-poll). Bounded: exits after
 * BOUND_SECONDS (120, edit inline to change — `carrick trace` passes no macro
 * args) so a hung wait4 still produces a complete trace and exits cleanly.
 *
 * USAGE:
 *   sudo target/release/carrick trace -s scripts/dtrace/native-child-lifecycle.d \
 *     -o /tmp/ncl.out -- run <image> -- <cmd>
 */
#pragma D option quiet
#pragma D option strsize=128
#pragma D option bufsize=8m
#pragma D option switchrate=10hz

inline int BOUND_SECONDS = 120;

dtrace:::BEGIN
{
    printf("NCL1|header|version=1|bound_s=%d\n", BOUND_SECONDS);
    secs = 0;
    events = 0;
    errors = 0;
}

carrick*:::native-child-fork
/(pid == $target || progenyof($target))/
{
    events++;
    printf("NCL1|fork|ts=%llu|parent=%llu#%llu|child=%llu#%llu|exit_sig=%llu|flags=0x%llx\n",
        timestamp,
        (uint64_t)arg0, (uint64_t)arg1,
        (uint64_t)arg2, (uint64_t)arg3,
        (uint64_t)arg4 & 0xff, ((uint64_t)arg4 >> 8) & 0xff);
}

carrick*:::native-child-exec
/(pid == $target || progenyof($target))/
{
    events++;
    printf("NCL1|exec|ts=%llu|task=%llu#%llu|ok=%u|detail=%d\n",
        timestamp,
        (uint64_t)arg0, (uint64_t)arg1,
        (uint32_t)arg2, (int32_t)arg3);
}

carrick*:::native-child-exit
/(pid == $target || progenyof($target))/
{
    events++;
    printf("NCL1|exit|ts=%llu|task=%llu#%llu|reason_class=%u|reason_code=%u|wstatus=0x%04x\n",
        timestamp,
        (uint64_t)arg0, (uint64_t)arg1,
        (uint32_t)arg2, (uint32_t)arg3, (uint32_t)arg4);
}

carrick*:::native-child-zombie
/(pid == $target || progenyof($target))/
{
    events++;
    printf("NCL1|zombie|ts=%llu|child=%llu#%llu|parent=%llu#%llu\n",
        timestamp,
        (uint64_t)arg0, (uint64_t)arg1,
        (uint64_t)arg2, (uint64_t)arg3);
}

carrick*:::native-child-wake
/(pid == $target || progenyof($target))/
{
    events++;
    printf("NCL1|wake|ts=%llu|parent=%llu#%llu|wake_reason=%u|woken=%u\n",
        timestamp,
        (uint64_t)arg0, (uint64_t)arg1,
        (uint32_t)arg2, (uint32_t)arg3);
}

carrick*:::native-child-reap
/(pid == $target || progenyof($target))/
{
    events++;
    printf("NCL1|reap|ts=%llu|caller=%llu#%llu|child=%llu#%llu|wstatus=0x%04x\n",
        timestamp,
        (uint64_t)arg0, (uint64_t)arg1,
        (uint64_t)arg2, (uint64_t)arg3, (uint32_t)arg4);
}

dtrace:::ERROR
{
    errors++;
}

profile:::tick-1s
{
    secs++;
}

profile:::tick-1s
/secs >= BOUND_SECONDS/
{
    printf("NCL1|end|reason=bound|events=%d|errors=%d\n", events, errors);
    exit(events == 0 ? 2 : 0);
}

dtrace:::END
{
    printf("NCL1|end|reason=end|events=%d|errors=%d\n", events, errors);
}
