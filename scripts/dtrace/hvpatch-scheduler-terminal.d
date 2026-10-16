/*
 * Which failure is lowered to sibling-owned process termination failure?
 * Launch a signed scheduler test with carrick trace -- --external <binary>.
 *
 * ABI source-qualified at 0afca998c: terminal-error(pid,tid,cause),
 * executor-load-failure(thread,generation,executor,cause),
 * guest-lifecycle(phase,pid,ppid,tid,asid), guest-exit(pid,tid,asid,status),
 * guest-exit(host pid,exit code), trace-witness-exit(raw wait status).
 * Live-qualified on main d23336bcc and candidate 0afca998c: failed reloads
 * report task ASID 1 with TTBRs lacking that ASID, followed by the external
 * witness's failure status. Both captures have zero probe errors.
 *
 * Perturbation: lifecycle and failure events only; no performance claim.
 * Scope includes the external witness's descendants. Bound is 45 seconds;
 * the operator reaps only its CARRICK_RUN_ID after the consumer ends.
 * A successful trace means captured events, not a successful test: retain
 * the witness wait status and its separate test output.
 */
#pragma D option quiet
#pragma D option strsize=1024
#pragma D option bufsize=4m

BEGIN { started=timestamp; events=0; errors=0; }
carrick*:::hvpatch-executor-load-failure
/pid == $target || progenyof($target)/
{ printf("SCHEDTERM1|load-failure|ts=%llu|host=%d|thread=%llu|gen=%llu|executor=%u|cause=%s\n",
    timestamp,pid,(uint64_t)arg0,(uint64_t)arg1,(uint32_t)arg2,copyinstr(arg3)); }
carrick*:::hvpatch-guest-lifecycle
/pid == $target || progenyof($target)/
{ events++; printf("SCHEDTERM1|life|ts=%llu|host=%d|phase=%u|pid=%d|tid=%d|asid=%u\n",
    timestamp,pid,(uint32_t)arg0,(int32_t)arg1,(int32_t)arg3,(uint32_t)arg4); }
carrick*:::hvpatch-terminal-error
/pid == $target || progenyof($target)/
{ printf("SCHEDTERM1|error|ts=%llu|host=%d|pid=%d|tid=%d|cause=%s\n",
    timestamp,pid,(int32_t)arg0,(int32_t)arg1,copyinstr(arg2)); }
carrick*:::hvpatch-guest-exit
/pid == $target || progenyof($target)/
{ printf("SCHEDTERM1|exit|ts=%llu|host=%d|pid=%d|tid=%d|status=%d\n",
    timestamp,pid,(int32_t)arg0,(int32_t)arg1,(int32_t)arg3); }
carrick*:::guest-exit
/pid == $target || progenyof($target)/
{ printf("SCHEDTERM1|result|ts=%llu|host=%d|code=%d\n",
    timestamp,pid,(int32_t)arg1); }
carrick*:::trace-witness-exit
/pid == $target/
{ printf("SCHEDTERM1|witness|wait_status=%d\n",(int32_t)arg0);
  exit(events > 0 && errors == 0 ? 0 : 2); }
proc:::exit /pid == $target/ { exit(events > 0 && errors == 0 ? 0 : 2); }
dtrace:::ERROR { errors++; }
profile:::tick-1sec /timestamp-started >= 45ULL*1000000000ULL/ { exit(3); }
END { printf("SCHEDTERM1|end|events=%d|errors=%d|elapsed_ns=%llu\n",events,errors,timestamp-started); }
