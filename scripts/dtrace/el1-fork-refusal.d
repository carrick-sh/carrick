#pragma D option quiet
#pragma D option bufsize=4m
/*
 * WHERE DOES AN OWNER FORK STOP AFTER CHILD ROOT PUBLICATION?
 * Measures existing root, BIND, clone outcome and fork runtime/spec stages.
 * ABI: root-prepublish(mm,phase), owner-bind-result(errno), runtime-stage
 * (phase,parent,child,tid,ns), process-spec-stage(phase,child,tid,ns,units),
 * mn-clone-outcome(tid,phase,errno), syscall-return(nr,name,result,guest-pid).
 * Root/BIND ABI is live-qualified by el1-root-admission.d. Fork stage ABI
 * is described in hvpatch-phase4-fork-runtime-stages.d and its spec peer.
 * The retained 1dfba1500 embed fixture disables the syscall-return observer;
 * no return events therefore cannot establish the guest errno. Its owner
 * Fork adapter has no service-result USDT, so this profile cannot infer the
 * internal refusal stage. Live-qualified on 1dfba1500, 2026-10-05:
 * VMA and ptrace-clone captures both reached runtime phases 0,1,2 and
 * child MM 3 prepublish phase 9, then failed before runtime phase 3. Each
 * had four root controls, zero return events, zero errors and zero drops.
 * Perturbation: scalar lifecycle events, no stacks or descriptor walks.
 */
carrick*:::hvpatch-el1-root-prepublish
/pid == $target || progenyof($target)/
{ controls++; printf("EL1FORK ns=%d root mm=%d phase=%d\n",timestamp,arg0,arg1); }
carrick*:::hvpatch-el1-owner-bind-result
/pid == $target || progenyof($target)/
{ printf("EL1FORK ns=%d bind errno=%d\n",timestamp,arg0); }
carrick*:::hvpatch-fork-runtime-stage
/pid == $target || progenyof($target)/
{ printf("EL1FORK ns=%d runtime phase=%d parent=%d child=%d tid=%d elapsed=%d\n",timestamp,arg0,arg1,arg2,arg3,arg4); }
carrick*:::hvpatch-fork-process-spec-stage
/pid == $target || progenyof($target)/
{ printf("EL1FORK ns=%d spec phase=%d child=%d tid=%d elapsed=%d units=%d\n",timestamp,arg0,arg1,arg2,arg3,arg4); }
carrick*:::mn-clone-outcome
/pid == $target || progenyof($target)/
{ printf("EL1FORK ns=%d clone tid=%d phase=%d errno=%d\n",timestamp,arg0,arg1,arg2); }
carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (arg0 == 220 || arg0 == 435)/
{ returns++; printf("EL1FORK ns=%d return nr=%d result=%d\n",timestamp,arg0,(int64_t)arg2); }
proc:::exit
/pid == $target/
{ exited=1; exit(0); }
tick-1s
{ seconds++; }
tick-1s
/seconds >= 60 && !exited/
{ exit(4); }
dtrace:::ERROR
{ errors++; }
dtrace:::DROP
{ drops++; }
END
{
    printf("EL1FORK controls=%d returns=%d exited=%d errors=%d drops=%d\n",controls,returns,exited,errors,drops);
    if (controls == 0 || errors != 0 || drops != 0 || !exited) { exit(4); }
}
