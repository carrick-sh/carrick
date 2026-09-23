#!/usr/sbin/dtrace -qs
/* Locate coarse fork/exec service costs for the Node minimal-child reduction.
 * ABI from probes.rs, Darwin arm64: fork runtime phase,parent pid,child pid,
 * parent tid,ns; fork spec phase,child pid,parent tid,ns,units; exec runtime
 * and exec replacement phase,ns,regions,bytes. Qualified by nonzero live rows.
 * Fork phase9 encloses 0..8; spec11 encloses 0..10; exec runtime4 encloses
 * replacement phases. NEVER add nested ledgers. Exec lacks Linux task identity;
 * host thread and timestamp are retained, not asserted to be guest identities.
 * LOW event-rate USDT perturbation, still no untraced speedup attribution.
 * Natural root exit, nonzero events and zero errors required at 10s bound.
 */
#pragma D option quiet
#pragma D option bufsize=16m
BEGIN { seconds=0; seen=0; errors=0; root_exited=0; }
carrick*:::hvpatch-fork-runtime-stage
/pid == $target || progenyof($target)/
{ seen=1; printf("CHILD1|fork|ts=%llu|phase=%u|parent=%d|child=%d|tid=%d|ns=%llu\n",timestamp,(uint32_t)arg0,(int)arg1,(int)arg2,(int)arg3,(uint64_t)arg4); }
carrick*:::hvpatch-fork-process-spec-stage
/pid == $target || progenyof($target)/
{ seen=1; printf("CHILD1|spec|ts=%llu|phase=%u|child=%d|tid=%d|ns=%llu|units=%llu\n",timestamp,(uint32_t)arg0,(int)arg1,(int)arg2,(uint64_t)arg3,(uint64_t)arg4); }
carrick*:::hvpatch-exec-runtime-stage
/pid == $target || progenyof($target)/
{ seen=1; printf("CHILD1|exec|ts=%llu|host=%d|tid=%d|phase=%u|ns=%llu\n",timestamp,pid,tid,(uint32_t)arg0,(uint64_t)arg1); }
carrick*:::hvpatch-exec-replace-stage
/pid == $target || progenyof($target)/
{ seen=1; printf("CHILD1|replace|ts=%llu|host=%d|tid=%d|phase=%u|ns=%llu\n",timestamp,pid,tid,(uint32_t)arg0,(uint64_t)arg1); }
proc:::exit /pid == $target/ { root_exited=1; }
dtrace:::ERROR { errors=1; }
tick-1s { seconds++; }
tick-1s /seconds >= 10/
{ printf("CHILD1|summary|seen=%d|errors=%d|root_exited=%d\n",seen,errors,root_exited); exit(seen && !errors && root_exited ? 0 : 2); }
