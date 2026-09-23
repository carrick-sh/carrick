#!/usr/sbin/dtrace -qs
/* Per-request madvise alignment, elapsed service and explicit scrub bytes.
 * Darwin arm64 ABI qualified from probes.rs and hvpatch-madvise-shape.d:
 * begin/end: guest pid,tid,asid,nr,end duration ns; args: nr,address,len,advice;
 * backing-scrub: total,zeroed,remapped,eligibility. Synchronous windows stay
 * on one host thread. Fail on nesting, missing args, wrong identity or errors.
 * No scrub event does NOT prove retirement. Other work and overlap remain.
 * MEDIUM perturbation: selected USDT windows; never use traced elapsed as
 * predicted savings. Natural target exit required at the ten second bound.
 */
#pragma D option quiet
#pragma D option bufsize=16m
#pragma D option dynvarsize=16m
BEGIN { seconds=0; errors=0; seen=0; exited=0; self->active=0; self->gp=0; self->gt=0; self->asid=0; self->args=0; self->address=(uint64_t)0; self->len=(uint64_t)0; self->advice=(uint64_t)0; self->total=(uint64_t)0; self->zeroed=(uint64_t)0; self->remapped=(uint64_t)0; }
carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) && arg3 == 233/
{ errors=errors || self->active; self->active=1; self->gp=arg0; self->gt=arg1; self->asid=arg2; self->args=0; self->total=(uint64_t)0; self->zeroed=(uint64_t)0; self->remapped=(uint64_t)0; seen=1; @counts["begin"]=count(); }
carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target)) && arg0 == 233/
{ errors=errors || !self->active || self->args; self->args=1; self->address=(uint64_t)arg1; self->len=(uint64_t)arg2; self->advice=(uint64_t)arg3; @counts["args"]=count(); }
carrick*:::hvpatch-backing-scrub
/(pid == $target || progenyof($target)) && self->active/
{ self->total+=arg0; self->zeroed+=arg1; self->remapped+=arg2; errors=errors || arg0 != arg1+arg2; }
carrick*:::hvpatch-syscall-service
/(pid == $target || progenyof($target)) && arg3 == 233/
{ errors=errors || !self->active || !self->args || self->gp!=arg0 || self->gt!=arg1 || self->asid!=arg2;
 printf("DISCARD1|pid=%d|tid=%d|advice=%llu|address=%llu|len=%llu|ns=%llu|scrub=%llu|zeroed=%llu|remapped=%llu\n",(int)arg0,(int)arg1,(uint64_t)self->advice,(uint64_t)self->address,(uint64_t)self->len,(uint64_t)arg4,(uint64_t)self->total,(uint64_t)self->zeroed,(uint64_t)self->remapped);
 @counts["end"]=count(); self->active=0; }
proc:::exit /pid == $target/ { exited=1; }
dtrace:::ERROR { errors=1; }
tick-1s { seconds++; }
tick-1s /seconds>=10/
{ printa("DISCARD1|count|kind=%s|n=%@d\n",@counts); printf("DISCARD1|summary|seen=%d|errors=%d|exited=%d\n",seen,errors,exited); exit(seen && !errors && exited ? 0 : 2); }
