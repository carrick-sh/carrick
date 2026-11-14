#pragma D option quiet
#pragma D option bufsize=8m
/*
 * WHERE DOES GO'S TELEMETRY SIDECAR START FAIL? (#2276, #2242)
 * `go version` (golang:1.23) vforks a zero-stack child that setsid()s,
 * chdir()s, dup3()s /dev/null and execs `go "** telemetry **"`. On ARM HVF
 * the root row dies with a bare SIGSEGV (139) and the go-hello row's child
 * reports EFAULT. This records every fault, terminal and refused signal
 * frame with its address and thread, the EL1 native diagnostics (their
 * reason strings name the refusing venue), and each failing return of the
 * calls on the sidecar path.
 * ABI: hvpatch-fault-delivery(far,incoming,delivered,bus,tid),
 * hvpatch-fault-terminal(far,signum,si_code,tid),
 * hvpatch-fault-signal-frame-failure(far,signum,tid),
 * hvpatch-signal-frame-step(step,va,len,error),
 * hvpatch-first-touch-refused(page,access,site,error),
 * el1-native-diagnostic(cpu,mm,root,reason), vcpu-fault(esr,elr,far,x30,sp,tid),
 * signal-inject(signum,saved_pc,new_sp,handler),
 * syscall-return(nr,name,result,guest-pid).
 * Usage (bounded): CARRICK_RUN_ID=go-sidecar-$$ timeout 180 carrick trace
 *   --script scripts/dtrace/go-sidecar-fault.d --trace-out <file> --
 *   run golang:1.23 go version
 * Perturbation: scalar events on failure paths only, no stacks.
 */
carrick*:::hvpatch-fault-delivery
/pid == $target || progenyof($target)/
{ printf("GOSIDE ns=%d fault-delivery far=0x%x incoming=%d delivered=%d bus=%d tid=%d\n",timestamp,arg0,arg1,arg2,arg3,arg4); }
carrick*:::hvpatch-fault-terminal
/pid == $target || progenyof($target)/
{ printf("GOSIDE ns=%d fault-terminal far=0x%x signum=%d code=%d tid=%d\n",timestamp,arg0,arg1,arg2,arg3); }
carrick*:::hvpatch-fault-signal-frame-failure
/pid == $target || progenyof($target)/
{ printf("GOSIDE ns=%d frame-failure far=0x%x signum=%d tid=%d\n",timestamp,arg0,arg1,arg2); }
carrick*:::hvpatch-signal-frame-step
/(pid == $target || progenyof($target)) && arg3 != 0/
{ printf("GOSIDE ns=%d frame-step step=%d va=0x%x len=%d error=%d\n",timestamp,arg0,arg1,arg2,arg3); }
carrick*:::hvpatch-first-touch-refused
/pid == $target || progenyof($target)/
{ printf("GOSIDE ns=%d first-touch-refused page=0x%x access=%d site=%d error=%s\n",timestamp,arg0,arg1,arg2,copyinstr(arg3)); }
carrick*:::el1-native-diagnostic
/pid == $target || progenyof($target)/
{ printf("GOSIDE ns=%d el1 cpu=%d mm=%d root=0x%x %s\n",timestamp,arg0,arg1,arg2,copyinstr(arg3)); }
carrick*:::vcpu-fault
/pid == $target || progenyof($target)/
{ printf("GOSIDE ns=%d vcpu-fault esr=0x%x elr=0x%x far=0x%x x30=0x%x sp=0x%x tid=%d\n",timestamp,arg0,arg1,arg2,arg3,arg4,arg5); }
carrick*:::signal-inject
/(pid == $target || progenyof($target)) && arg0 != 23/
{ printf("GOSIDE ns=%d signal-inject signum=%d pc=0x%x sp=0x%x handler=0x%x\n",timestamp,arg0,arg1,arg2,arg3); }
carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (int64_t)arg2 < 0 &&
 (arg0 == 220 || arg0 == 221 || arg0 == 49 || arg0 == 24 || arg0 == 157 ||
  arg0 == 434 || arg0 == 222 || (int64_t)arg2 == -14)/
{ printf("GOSIDE ns=%d return nr=%d result=%d guest-pid=%d\n",timestamp,arg0,(int64_t)arg2,arg3); }
tick-1s { secs++; }
tick-1s /secs >= 150/ { exit(0); }
proc:::exit
/pid == $target/
{ exit(0); }
