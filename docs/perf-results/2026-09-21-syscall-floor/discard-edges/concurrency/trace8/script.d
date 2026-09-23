#!/usr/sbin/dtrace -qs
/* Aggregate topology/MM transaction and frame-registry waits by operation.
 * Darwin arm64 ABI from probes.rs: operation0..10, phase0=request,1=acquired,
 * 2=released,3=try-miss; guest pid,tid; arg4 wait/hold/attempt nanoseconds.
 * These probes cover different locks, so do NOT infer one global holder or
 * add nested holds. Concurrent waits overlap and are not removable wall time.
 * Validate per-operation request=acquire+miss and acquire=release in reader.
 * MEDIUM perturbation: aggregate USDT on each lock edge; no timed-win claim.
 * Ten-second bound; natural root exit, nonzero events and no errors required.
 */
#pragma D option quiet
#pragma D option aggsize=16m
BEGIN { seconds=0; seen=0; errors=0; exited=0; }
carrick*:::hvpatch-topology-lock
/pid == $target || progenyof($target)/
{ seen=1; errors=errors || arg0>10 || arg1>3; @count[(uint32_t)arg0,(uint32_t)arg1]=count(); @ns[(uint32_t)arg0,(uint32_t)arg1]=sum((uint64_t)arg4); @max[(uint32_t)arg0,(uint32_t)arg1]=max((uint64_t)arg4); }
proc:::exit /pid == $target/ { exited=1; }
dtrace:::ERROR { errors=1; }
tick-1s { seconds++; }
tick-1s /seconds>=10/
{ printa("TOPOB1|count|op=%u|phase=%u|v=%@d\n",@count); printa("TOPOB1|ns|op=%u|phase=%u|v=%@d\n",@ns); printa("TOPOB1|max|op=%u|phase=%u|v=%@d\n",@max); printf("TOPOB1|summary|seen=%d|errors=%d|exited=%d\n",seen,errors,exited); exit(seen && !errors && exited ? 0 : 2); }
