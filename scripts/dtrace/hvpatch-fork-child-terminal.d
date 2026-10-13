/*
 * What does a fork child do between backend load and exit 127?
 *
 * Ordered child Linux syscall entry/return, lifecycle and exact exit status,
 * plus owner write preparation/refusal. Root syscalls are aggregated so the
 * known rt_sigsuspend ENOSYS spin cannot flood the consumer. A child with no
 * syscall entries needs a terminal cause to distinguish bootstrap/entry
 * failure from entirely in-ring service; absence alone proves nothing.
 *
 * ABI source-qualified against carrick-observability at f089f3cc1:
 * service-begin(pid,tid,asid,nr), syscall-args(nr,a0,a1,a2,a3),
 * syscall-return(nr,name,value,errno), guest-lifecycle(phase,pid,ppid,tid,asid),
 * guest-exit(pid,tid,asid,status), host-write-prepare(va,len,phase,detail),
 * internal-write-fault(va,len,phase,error), terminal-error(pid,tid,cause).
 * Terminal-error records the cause before lowering; it is not an exit receipt.
 * Live-qualified: pid 2 identity commits precede a terminal error reporting
 * child TID Supply(Cow) at 0x6000000fd0, MM 3, with zero probe errors.
 * Perturbation: syscall providers are enabled, but only child calls print;
 * no guest bytes, stacks, host syscall stream or performance claim.
 * Bound starts at root birth (45s), with a 300s startup bound. The operator
 * reaps only the unique guest run-id after the consumer has ended.
 */
#pragma D option quiet
#pragma D option strsize=512
#pragma D option bufsize=16m

BEGIN { armed=timestamp; started=0; errors=0; roots=0; forks=0; exits=0; terminal_errors=0; child_calls=0; root_calls=0; }

carrick*:::hvpatch-syscall-service-begin
/pid == $target || progenyof($target)/
{ self->lpid=(int32_t)arg0; self->ltid=(int32_t)arg1; self->nr=(uint64_t)arg3;
  root_calls += self->lpid == 1; child_calls += self->lpid > 1; }

carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target)) && self->lpid > 1 && arg0 == self->nr/
{ printf("FCT1|entry|ts=%llu|pid=%d|tid=%d|nr=%llu|a0=%llx|a1=%llx|a2=%llx|a3=%llx\n",
    timestamp,self->lpid,self->ltid,(uint64_t)arg0,(uint64_t)arg1,(uint64_t)arg2,(uint64_t)arg3,(uint64_t)arg4); }

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && self->lpid > 1/
{ printf("FCT1|ret|ts=%llu|pid=%d|tid=%d|nr=%llu|name=%s|value=%lld|errno=%d\n",
    timestamp,self->lpid,self->ltid,(uint64_t)arg0,copyinstr(arg1),(int64_t)arg2,(int32_t)arg3); }

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && self->lpid == 1/
{ @root_returns[(uint64_t)arg0,(int32_t)arg3]=count(); }

carrick*:::hvpatch-guest-lifecycle
/pid == $target || progenyof($target)/
{ roots += arg0 == 0; forks += arg0 == 1;
  started = arg0 == 0 && started == 0 ? timestamp : started;
  printf("FCT1|life|ts=%llu|phase=%u|pid=%d|ppid=%d|tid=%d|asid=%u\n",timestamp,
    (uint32_t)arg0,(int32_t)arg1,(int32_t)arg2,(int32_t)arg3,(uint32_t)arg4); }

carrick*:::hvpatch-guest-exit
/pid == $target || progenyof($target)/
{ exits++; printf("FCT1|exit|ts=%llu|pid=%d|tid=%d|asid=%u|status=%d\n",timestamp,
    (int32_t)arg0,(int32_t)arg1,(uint32_t)arg2,(int32_t)arg3); }

carrick*:::hvpatch-el1-host-write-prepare
/pid == $target || progenyof($target)/
{ printf("FCT1|write|ts=%llu|host_tid=%d|va=%llx|len=%llu|phase=%u|detail=%llu\n",
    timestamp,tid,(uint64_t)arg0,(uint64_t)arg1,(uint32_t)arg2,(uint64_t)arg3); }

carrick*:::guest-internal-write-fault
/pid == $target || progenyof($target)/
{ printf("FCT1|write-fault|ts=%llu|host_tid=%d|va=%llx|len=%llu|phase=%u|error=%s\n",
    timestamp,tid,(uint64_t)arg0,(uint64_t)arg1,(uint32_t)arg2,copyinstr(arg3)); }

carrick*:::hvpatch-terminal-error
/pid == $target || progenyof($target)/
{ terminal_errors++; printf("FCT1|terminal-error|ts=%llu|pid=%d|tid=%d|cause=%s\n",
    timestamp,(int32_t)arg0,(int32_t)arg1,copyinstr(arg2)); }

dtrace:::ERROR { errors++; }
proc:::exit /pid == $target/ { exit(errors == 0 && forks > 0 ? 0 : 2); }
profile:::tick-1sec
/(started != 0 && timestamp-started >= 45ULL*1000000000ULL) ||
 (started == 0 && timestamp-armed >= 300ULL*1000000000ULL)/
{ exit(errors == 0 && forks > 0 && (exits > 0 || terminal_errors > 0) ? 0 : 2); }
END { printa("FCT1|root-return|nr=%llu|errno=%d|count=%@d\n",@root_returns);
  printf("FCT1|end|ts=%llu|elapsed_ns=%llu|roots=%d|forks=%d|exits=%d|terminal_errors=%d|child_calls=%d|root_calls=%d|errors=%d\n",
    timestamp,timestamp-armed,roots,forks,exits,terminal_errors,child_calls,root_calls,errors); }
