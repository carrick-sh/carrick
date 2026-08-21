/*
 * HVPatch persistent-executor lifecycle census.
 *
 * Measures whether host pthread and Hypervisor.framework vCPU materialization
 * stays bounded while Linux guest clone/fork activity grows. It also records
 * the existing M:N admission/reclaim probes used as the pre-persistent switch
 * boundary. This script is observational but potentially perturbing on clone-
 * heavy workloads; compare only captures made with this same script.
 *
 * Provider ABI qualification (macOS 26.0, arm64, 2026-08-21):
 * - carrick:::mn-admit(tid, slot, budget), mn-reclaim(tid, old, new, kind),
 *   and mn-clone-outcome(tid, phase, errno) are the checked-in USDT ABI;
 * - syscall:::bsdthread_create and bsdthread_terminate are Darwin pthread
 *   lifecycle syscalls;
 * - pid$target::*create_vcpu* names Carrick's two owner-thread HVF creation
 *   wrappers (`create_vcpu` and `create_vcpu_with_permit`); each successful
 *   wrapper calls `vcpu_created` once. `*vcpu_destroyed*` is Carrick's exact
 *   post-success hook after raw `hv_vcpu_destroy`.
 *
 * The pid provider deliberately binds only the one HVPatch VM carrier. HVPatch
 * guest fork/clone must not create a Darwin child; syscall/USDT clauses retain
 * progenyof($target) so an unexpected host materializer remains visible.
 */

#pragma D option quiet

BEGIN
{
    secs = 0;
}

syscall::bsdthread_create:entry
/pid == $target || progenyof($target)/
{
    @host_pthread_create = count();
}

syscall::bsdthread_terminate:entry
/pid == $target || progenyof($target)/
{
    @host_pthread_terminate = count();
}

pid$target::*create_vcpu*:entry
{
    @hvf_vcpu_create[probefunc] = count();
}

pid$target::*vcpu_destroyed*:entry
{
    @hvf_vcpu_destroy = count();
}

carrick*:::mn-admit
/pid == $target || progenyof($target)/
{
    @mn_admit = count();
}

carrick*:::mn-reclaim
/pid == $target || progenyof($target)/
{
    @mn_reclaim_kind[arg3] = count();
}

carrick*:::mn-clone-outcome
/pid == $target || progenyof($target)/
{
    @guest_clone_phase[arg1] = count();
    @guest_clone_errno[arg2] = count();
}

carrick*:::hvpatch-executor-lifecycle
/pid == $target || progenyof($target)/
{
    @executor_lifecycle[arg0, arg1] = count();
}

tick-1s
{
    secs++;
}

tick-1s
/secs >= 30/
{
    exit(0);
}

END
{
    printa("CENSUS host_pthread_create %@d\n", @host_pthread_create);
    printa("CENSUS host_pthread_terminate %@d\n", @host_pthread_terminate);
    printa("CENSUS hvf_vcpu_create function=%s count=%@d\n", @hvf_vcpu_create);
    printa("CENSUS hvf_vcpu_destroy %@d\n", @hvf_vcpu_destroy);
    printa("CENSUS mn_admit %@d\n", @mn_admit);
    printa("CENSUS mn_reclaim_kind kind=%d count=%@d\n", @mn_reclaim_kind);
    printa("CENSUS guest_clone_phase phase=%d count=%@d\n", @guest_clone_phase);
    printa("CENSUS guest_clone_errno errno=%d count=%@d\n", @guest_clone_errno);
    printa("CENSUS executor_lifecycle executor=%d phase=%d count=%@d\n",
        @executor_lifecycle);
}
