#!/usr/sbin/dtrace -Zqs
/*
 * hvpatch-el1-frame-grant-call-census.d — identify which host first-touch
 * transaction runs after the EL1 fault vector forwards an mmap translation.
 *
 * WHAT IT MEASURES
 *   Counts the exact frame-grant claim/plan/backend/commit functions and the
 *   legacy one-page resident-fault commit in the traced Carrick process. The
 *   accompanying vcpu-fault count and PID split prove whether the carrier is
 *   the pid$target process; a zero pid-provider count is evidence only when
 *   target_faults is nonzero.
 *
 * PROVIDER ABI
 *   The five Rust symbols were qualified live with `nm -nm` on the exact
 *   signed release binary. pid$target does not follow a host fork, so invoke
 *   this census with `run-elf --pid host`; `carrick*:::vcpu-fault` remains the
 *   independent process-placement control.
 *
 * PERTURBATION
 *   Entry probes only. This is correctness attribution, never timing
 *   evidence. Zero vcpu faults in the target process, DTrace errors, drops or
 *   a timeout fail the capture.
 */

#pragma D option bufsize=8m
#pragma D option aggsize=8m

dtrace:::BEGIN
{
    live = 1;
    seconds = 0;
    complete = 0;
    all_faults = 0;
    target_faults = 0;
    claims = 0;
    plans = 0;
    prepares = 0;
    pristine_checks = 0;
    retirement_plans = 0;
    publications = 0;
    grant_commits = 0;
    page_commits = 0;
    drops = 0;
    errors = 0;
    printf("EL1GRANTCALL1|start|ns=%d|target=%d\n", timestamp, $target);
}

carrick*:::vcpu-fault
/pid == $target || progenyof($target)/
{
    all_faults++;
    target_faults += pid == $target;
    @fault_pid[pid] = count();
}

pid$target::*claim_frame_grant_request*:entry
{
    claims++;
}

pid$target::*resident_frame_grant_plan*:entry
{
    plans++;
}

pid$target::*prepare_el1_frame_grant*:entry
{
    prepares++;
}

pid$target::*begin_pristine_materialization*:entry
{
    pristine_checks++;
}

pid$target::*plan_process_alias_retirement*:entry
{
    retirement_plans++;
}

pid$target::*publish_frame_grant*:entry
{
    publications++;
}

pid$target::*commit_resident_frame_grant*:entry
{
    grant_commits++;
}

pid$target::*commit_resident_fault*:entry
{
    page_commits++;
}

proc:::exit
/pid == $target/
{
    live = 0;
}

tick-100ms
/live == 0 && !complete/
{
    complete = 1;
    errors += all_faults == 0 || target_faults == 0 || drops != 0;
    exit(errors == 0 ? 0 : 5);
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 30 && !complete/
{
    complete = 1;
    printf("EL1GRANTCALL1|TRUNCATED|seconds=%d\n", seconds);
    exit(4);
}

dtrace:::DROP
{
    drops++;
}

dtrace:::ERROR
{
    errors++;
}

dtrace:::END
{
    printf("EL1GRANTCALL1|summary|all_faults=%d|target_faults=%d|claims=%d|plans=%d|prepares=%d|pristine_checks=%d|retirement_plans=%d|publications=%d|grant_commits=%d|page_commits=%d|drops=%d|errors=%d\n",
        all_faults, target_faults, claims, plans, prepares, pristine_checks,
        retirement_plans, publications, grant_commits, page_commits, drops,
        errors);
    printa("EL1GRANTCALL1|fault_pid|%d|%@d\n", @fault_pid);
}
