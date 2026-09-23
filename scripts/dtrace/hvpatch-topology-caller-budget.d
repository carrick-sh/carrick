#!/usr/sbin/dtrace -qs
/* Distinguish frame-registry critical sections from MM transaction scopes.
 * Darwin arm64 qualified ABI: hvpatch-topology-lock args0 operation,1 phase,
 * 2 guest pid,3 guest tid,4 duration ns. All current nonzero acquisition waits
 * come from FrameRegistryGuard; MM transaction depth acquisition emits zero.
 * ustack(16) names actual acquire/release call sites, including inlined callers.
 * HIGH perturbation: stack capture on each acquire/release. Durations include
 * instrumentation; overlapping waits and nested holds are NOT removable time.
 * Require natural guest/root completion, all phases balanced, zero errors/drops.
 * One workload wave; twenty-second diagnostic bound, not a benchmark timeout.
 */
#pragma D option quiet
#pragma D option aggsize=32m
BEGIN { seconds=0; seen=0; errors=0; exited=0; }
carrick*:::hvpatch-topology-lock
/pid == $target || progenyof($target)/
{ seen=1; errors=errors || arg0>10 || arg1>3; @count[(uint32_t)arg0,(uint32_t)arg1]=count(); }
carrick*:::hvpatch-topology-lock
/(pid == $target || progenyof($target)) && arg1==1/
{ @wait[(uint32_t)arg0,ustack(16)]=sum((uint64_t)arg4); }
carrick*:::hvpatch-topology-lock
/(pid == $target || progenyof($target)) && arg1==2/
{ @hold[(uint32_t)arg0,ustack(16)]=sum((uint64_t)arg4); }
proc:::exit /pid == $target/ { exited=1; }
dtrace:::ERROR { errors=1; }
tick-1s { seconds++; }
tick-1s /seconds>=20/
{ printa("TCB1|count|op=%u|phase=%u|v=%@d\n",@count); printf("TCB1|wait-stacks\n"); printa(@wait); printf("TCB1|hold-stacks\n"); printa(@hold); printf("TCB1|summary|seen=%d|errors=%d|exited=%d\n",seen,errors,exited); exit(seen && !errors && exited ? 0 : 2); }
