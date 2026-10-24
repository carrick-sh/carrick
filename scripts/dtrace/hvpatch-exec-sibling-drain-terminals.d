#!/usr/sbin/dtrace -qs
/*
 * Order the per-thread terminal edges around an HVPatch execve(2) issued from
 * a multithreaded process, to attribute a SILENT exec death (carrier exits 0
 * with no guest output and no runtime-stage events) to the thread whose
 * terminal transition swallowed the exec.
 *
 * What it measures: every hvpatch-guest-lifecycle event (phase 6 = exec
 * begin, 2 = exec published, 4 = thread exit, 5 = process exit), every
 * hvpatch-thread-terminal receipt (reason 0 = guest exit(2), 1 = exec removed
 * the registry id at loop top — detail 1 when the process is exiting, 0 for
 * an exec drain; a reason-0 receipt with code 0 follows from the same
 * thread, 2 = ... after a blocking wait, 3 = vfork parent cancellation,
 * 4 = process-terminal loser — detail 1 from the Busy thread-exit arm,
 * 2 from a LostToExec/AlreadyOwned terminal claim, 5 = the drain OWNER
 * published `detail` member ThreadDone results externally — stamped with the
 * owner's identity, this is the only receipt a member that never finished
 * its own job gets, 6 = the thread was externally settled WITHOUT a result
 * of its own — `detail` is the HvpatchProductionPhase ordinal it was parked
 * in (0 Resident … 8 ExecSiblingDrain … 12 Complete); a reason-6 receipt
 * with detail 8 on the EXEC OWNER is the signature of the 2026-09-01
 * execthreads defect, where the exec reservation retired the predecessor mm
 * before the sibling drain and the owner's resume load was refused as
 * Retiring), every hvpatch-exec-runtime-stage
 * phase, and the execve/exit/exit_group syscall service boundaries
 * (AArch64 nr 221/93/94), each stamped with the relative nanosecond clock and
 * the host thread id.
 *
 * Provider ABI qualified on macOS 26.0 / arm64 on 2026-09-01:
 * - carrick*:::hvpatch-guest-lifecycle args: phase u32, pid i32, ppid i32,
 *   tid i32, asid u32.
 * - carrick*:::hvpatch-thread-terminal args: pid i32, linux tid i32,
 *   registry tid i32, reason u32, detail i32.
 * - carrick*:::hvpatch-exec-runtime-stage args: phase u32, elapsed ns u64,
 *   region count u64, mapped bytes u64.
 * - carrick*:::hvpatch-syscall-service-begin / hvpatch-syscall-service args:
 *   pid i32, tid i32, asid u32, nr u32 (+ duration ns on the completion).
 * - carrick*:::hvpatch-executor-load-failure args: thread serial u64,
 *   execution generation u64, executor u32, error C string. Source-qualified;
 *   a capture must see this row before attributing a backend load refusal.
 * - carrick*:::hvpatch-executor-failure args: executor u32, error C string.
 *   Source-qualified; covers the whole worker lifecycle, including native
 *   service on idle executors without a host task binding.
 *   Live-qualified on cloudmac 2026-10-23: executor 4 reports a fresh
 *   inventory mapping with generation 5 where the owner requires 1, after
 *   reason-6 settlement of the root's zone continuation (detail 14).
 * - carrick*:::trace-witness-exit args: external launcher's raw wait status.
 *   Ends captures of scripts/test-signed.sh after its scoped cleanup.
 * - carrick*:::hvpatch-native-crossing-refused args: MM, MM incarnation,
 *   record id, service sequence, native ordinal. Source-qualified; distinguishes
 *   a ring-owned refusal from a failing host executor.
 * - carrick*:::hvpatch-native-fault-supply args: MM, sequence, phase, fault
 *   page, selected length. Phases: 0 COW, 1 backing, 2 supplied, 3 refused,
 *   4 owner wait, 5 backing fault, 6 no selected supply window. Completion
 *   rows have zero page/length; unselected requests have zero length.
 *
 * PERTURBATION: LOW — only the selected syscalls and lifecycle edges print;
 * the sched_yield storm the reproducer generates is not instrumented.
 * Native refusals print only their first eight rows per MM/ordinal and
 * aggregate the full count; refusal-loop captures are not timing evidence.
 * A reason-6 settlement also captures its host stack, so an unexpected
 * executor-failure retirement can be attributed to its actual caller.
 * Zero lifecycle events makes the capture fail closed (exit 1). Bound guest
 * execution at 120 seconds from first lifecycle event, with a separate 300s
 * startup bound for the signed launcher's build and signing. This does not
 * change the signed test's own deadline. Provider errors fail the capture.
 */

#pragma D option quiet
#pragma D option strsize=1024

dtrace:::BEGIN
{
    started = timestamp;
    lifecycle = 0;
    guest_started = 0;
    errors = 0;
}

carrick*:::hvpatch-guest-lifecycle
/pid == $target || progenyof($target)/
{
    lifecycle++;
    guest_started = guest_started == 0 ? timestamp : guest_started;
    printf("%12d host_tid=%d lifecycle phase=%d pid=%d ppid=%d tid=%d asid=%d\n",
        timestamp - started, tid, arg0, arg1, arg2, arg3, arg4);
}

carrick*:::hvpatch-thread-terminal
/pid == $target || progenyof($target)/
{
    printf("%12d host_tid=%d thread-terminal pid=%d linux_tid=%d registry_tid=%d reason=%d detail=%d\n",
        timestamp - started, tid, arg0, arg1, arg2, arg3, arg4);
}

carrick*:::hvpatch-thread-terminal
/(pid == $target || progenyof($target)) && arg3 == 6/
{
    ustack(32);
}

carrick*:::hvpatch-executor-load-failure
/pid == $target || progenyof($target)/
{
    printf("%12d host_tid=%d load-failure thread_serial=%d generation=%d executor=%d error=%s\n",
        timestamp - started, tid, arg0, arg1, arg2, copyinstr(arg3));
    ustack(32);
}

carrick*:::hvpatch-exec-runtime-stage
/pid == $target || progenyof($target)/
{
    printf("%12d host_tid=%d exec-runtime-stage phase=%d elapsed_ns=%d regions=%d bytes=%d\n",
        timestamp - started, tid, arg0, arg1, arg2, arg3);
}

carrick*:::hvpatch-executor-failure
/pid == $target || progenyof($target)/
{
    printf("%12d host_tid=%d executor-failure executor=%d error=%s\n",
        timestamp - started, tid, arg0, copyinstr(arg1));
    ustack(32);
}

carrick*:::hvpatch-native-crossing-refused
/pid == $target || progenyof($target)/
{
    @refusals[arg0, arg4] = count();
    refusal_rows[arg0, arg4]++;
}

carrick*:::hvpatch-native-crossing-refused
/(pid == $target || progenyof($target)) && refusal_rows[arg0, arg4] <= 8/
{
    printf("%12d host_tid=%d native-crossing-refused mm=%d incarnation=%d record=%d sequence=%d ordinal=%d\n",
        timestamp - started, tid, arg0, arg1, arg2, arg3, arg4);
}

dtrace:::ERROR { errors++; }

carrick*:::hvpatch-native-fault-supply
/pid == $target || progenyof($target)/
{
    @faults[arg0, arg2, arg3] = count();
    fault_rows[arg0, arg2]++;
}

carrick*:::hvpatch-native-fault-supply
/(pid == $target || progenyof($target)) && fault_rows[arg0, arg2] <= 8/
{
    printf("%12d host_tid=%d native-fault mm=%d sequence=%d phase=%d page=0x%x length=%d\n",
        timestamp - started, tid, arg0, arg1, arg2, arg3, arg4);
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) && (arg3 == 221 || arg3 == 93 || arg3 == 94)/
{
    printf("%12d host_tid=%d syscall-begin pid=%d tid=%d asid=%d nr=%d\n",
        timestamp - started, tid, arg0, arg1, arg2, arg3);
}

carrick*:::hvpatch-syscall-service
/(pid == $target || progenyof($target)) && (arg3 == 221 || arg3 == 93 || arg3 == 94)/
{
    printf("%12d host_tid=%d syscall-done pid=%d tid=%d asid=%d nr=%d dur_ns=%d\n",
        timestamp - started, tid, arg0, arg1, arg2, arg3, arg4);
}

proc:::exit
/pid == $target/
{
    printf("%12d target-exit\n", timestamp - started);
    exit(lifecycle == 0 || errors != 0 ? 1 : 0);
}

carrick*:::trace-witness-exit
/pid == $target/
{
    printf("%12d witness-exit wait_status=%d\n", timestamp - started, arg0);
    exit(lifecycle == 0 || errors != 0 ? 1 : 0);
}

tick-1s
/(guest_started != 0 && timestamp - guest_started >= 120ULL * 1000000000ULL) ||
 (guest_started == 0 && timestamp - started >= 300ULL * 1000000000ULL)/
{
    printf("terminal-trace timeout\n");
    exit(2);
}

END
{
    printa("native-crossing-refused-total mm=%d ordinal=%d count=%@d\n", @refusals);
    printa("native-fault-total mm=%d phase=%d page=0x%x count=%@d\n", @faults);
    printf("terminal-trace end lifecycle=%d errors=%d\n", lifecycle, errors);
}
