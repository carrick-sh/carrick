#pragma D option quiet
#pragma D option bufsize=16m
#pragma D option ustackframes=24

/*
 * WHICH OWNER REFUSAL OR FAULT DECISION KILLED THE GUEST WITH SIGSEGV?
 *
 * (a) Measures, for the target and its descendants, every step that can turn
 *     a transient owner-memory state (owner wait, physical supply, physical
 *     wait) into a guest-visible failure, and every fault-to-signal
 *     decision, in one ordered stream:
 *     - host copyout prepare refusals (EFAULT class, #711),
 *     - host copyin refusals,
 *     - signal-frame build failures (force_sigsegv on the frame write),
 *     - first-touch faults delivered as a signal, with the reason,
 *     - clone TID output failures (CLONE_PARENT/CHILD_SETTID),
 *     - the terminal fault signal.
 *     Written for the #695/#711 control (`sock-pingpong-stepper`): after
 *     382a01d98, 1 of 20 runs still died with SIGSEGV and empty stderr
 *     within ~0.1 s, inside the second worker thread's spawn window.
 * (b) Provider ABI (from carrick-observability `probes.rs` signatures; NOT
 *     yet live-qualified, so qualify on the exact signed artifact first, and
 *     treat zero events from an arm as "did not fire", never "did not
 *     happen"):
 *     hvpatch-el1-host-write-prepare(va, len, phase, detail): phase 0 begin,
 *       1 supply (detail 1 grant, 2 COW, 3 metadata), 3 prepared, 4 owner
 *       wait (detail PortalWaitCause: 1 editor, 2 reservations, 3 pending
 *       edit, 4 gate, 5 metadata, 6 reservation pool), 5 physical wait,
 *       6 fault (1 bounds, 2 host map, 3 retired, 4 unsupported,
 *       5 metadata allocation, 6 other), 7 limit. Phase semantics are the
 *       ones live-qualified in el1-host-read-progress.d.
 *     hvpatch-el1-host-read-progress(va, len, offset, class, detail):
 *       class 2 physical wait, 3 owner wait (detail PortalWaitCause),
 *       4 supply, 6 refused (detail errno); 0/1 are progress and not printed.
 *     hvpatch-signal-frame-step(step, sp, len, error): step 1 prepare, 2 not
 *       writable, 3 frame write; error = sigframe memory code (1 bounds,
 *       2 unsupported, 3 host map, 4 metadata, 5 owner wait, 6 supply,
 *       7 physical, 8 read suspended, 9 owner retired). 5/6/7 on a valid
 *       stack mean a transient refusal became force_sigsegv.
 *     hvpatch-first-touch-deliver(far, reason, tid): reason 0 not tracked,
 *       1 no pending edit, 2 arming denies, 3 backend refused, 4 stale leaf
 *       not retried.
 *     hvpatch-first-touch-refused(page, access, site, error string).
 *     mn-clone-tid-output(tid, output, address, result): output 0 parent,
 *       1 child; result 0 success, 1 bounds, 2 unsupported, 3 host map,
 *       4 sparse backing, 5 frame COW, 6 metadata allocation, 7 suspended
 *       (a transient owner refusal; the clone then returns EFAULT, #711).
 *     hvpatch-guest-fault(esr, elr, far, guest pid, guest tid) and
 *     hvpatch-fault-terminal(far, signal, si_code, guest tid): the same
 *     arms as el1-host-read-progress.d.
 * (c) Perturbation: prints only refusals, failures and fault decisions,
 *     with a user stack on each refusal; successful copies are not printed.
 *     Ordering evidence only, never an uninstrumented verdict. Bounded at
 *     60 s; the session ends at target exit.
 *
 * Use (the guest workload; the static fixture runs without an image):
 *   carrick trace --script scripts/dtrace/hvpatch-owner-refusal-to-sigsegv.d \
 *     -- run-elf --raw target/embed-fixtures/el1-sched-aarch64 \
 *     sock-pingpong-stepper 2000
 * or against the signed embed control executable directly:
 *   sudo dtrace -Z -s scripts/dtrace/hvpatch-owner-refusal-to-sigsegv.d \
 *     -c '<signed el1_sched-<hash>> el1_sched_sock_pingpong_stepper_without_hold --exact --nocapture'
 */

proc:::exit
/pid == $target/
{
    target_exited = 1;
    exit(0);
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 60 && !target_exited/
{
    printf("OWNERSEGV1|truncated|seconds=%d\n", seconds);
    exit(0);
}

dtrace:::ERROR
{
    printf("OWNERSEGV1|dtrace-error|fault=%d\n", arg4);
}

carrick*:::hvpatch-el1-host-write-prepare
/(pid == $target || progenyof($target)) && (arg2 == 1 || arg2 >= 4)/
{
    printf("OWNERSEGV1|ns=%d|tid=%d|copyout-refusal|va=0x%x|len=%d|phase=%d|detail=%d\n",
        timestamp, tid, arg0, arg1, arg2, arg3);
    @refusals["copyout", arg2, arg3] = count();
    ustack();
}

carrick*:::hvpatch-el1-host-read-progress
/(pid == $target || progenyof($target)) && arg3 >= 2 && arg3 != 5/
{
    printf("OWNERSEGV1|ns=%d|tid=%d|copyin-refusal|va=0x%x|len=%d|offset=%d|class=%d|detail=%d\n",
        timestamp, tid, arg0, arg1, arg2, arg3, arg4);
    @refusals["copyin", arg3, arg4] = count();
    ustack();
}

carrick*:::hvpatch-signal-frame-step
/pid == $target || progenyof($target)/
{
    printf("OWNERSEGV1|ns=%d|tid=%d|sigframe-failure|step=%d|sp=0x%x|len=%d|error=%d\n",
        timestamp, tid, arg0, arg1, arg2, arg3);
    @refusals["sigframe", arg0, arg3] = count();
    ustack();
}

carrick*:::hvpatch-first-touch-deliver
/pid == $target || progenyof($target)/
{
    printf("OWNERSEGV1|ns=%d|first-touch-deliver|far=0x%x|reason=%d|guest-tid=%d\n",
        timestamp, arg0, arg1, arg2);
    @refusals["first-touch-deliver", arg1, 0] = count();
}

carrick*:::hvpatch-first-touch-refused
/pid == $target || progenyof($target)/
{
    printf("OWNERSEGV1|ns=%d|first-touch-refused|page=0x%x|access=%d|site=%d|error=%s\n",
        timestamp, arg0, arg1, arg2, copyinstr(arg3));
}

carrick*:::mn-clone-tid-output
/(pid == $target || progenyof($target)) && arg3 != 0/
{
    printf("OWNERSEGV1|ns=%d|clone-tid-failure|tid=%d|output=%d|va=0x%x|result=%d\n",
        timestamp, arg0, arg1, arg2, arg3);
    @refusals["clone-tid", arg1, arg3] = count();
}

carrick*:::hvpatch-guest-fault
/pid == $target || progenyof($target)/
{
    printf("OWNERSEGV1|ns=%d|guest-fault|esr=0x%x|elr=0x%x|far=0x%x|guest-pid=%d|guest-tid=%d\n",
        timestamp, arg0, arg1, arg2, arg3, arg4);
}

carrick*:::hvpatch-fault-terminal
/pid == $target || progenyof($target)/
{
    printf("OWNERSEGV1|ns=%d|fault-terminal|far=0x%x|signal=%d|si-code=%d|guest-tid=%d\n",
        timestamp, arg0, arg1, arg2, arg3);
}

END
{
    printa("OWNERSEGV1|summary|%s|a=%d|b=%d|count=%@d\n", @refusals);
}
