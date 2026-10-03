/*
 * Attribute required host-edit invalidations to the active guest syscall.
 * Attach to a signed embed executable with dtrace -C -Z -s this-file -p PID.
 * pid$target entry probes name debug Rust symbols; the syscall USDT arg0
 * is the Linux syscall number. Qualification requires both families firing.
 * This adds two events per edit and perturbs scheduling; counts, not timing,
 * are evidence. No guest memory is read. The trace ends itself at 120 s.
 * `-C -DUSDT_ONLY` removes the pid fasttrap sites to reduce perturbation;
 * pair that mode with the signed test's per-syscall debt counters.
 */
#pragma D option quiet
#pragma D option bufsize=16m

BEGIN { services = 0; owed_events = 0; }

carrick*:::syscall-entry
/pid == $target/
{ self->nr = arg0; }

carrick*:::hvpatch-syscall-service-begin
/pid == $target/
{ services++; self->nr = arg3; self->guest = arg1; }

carrick*:::hvpatch-syscall-args
/pid == $target && (arg0 == 215 || arg0 == 226 || arg0 == 222)/
{ printf("SYSCALL pid=%d tid=%d guest=%d nr=%d va=%x len=%d prot=%d\n", pid, tid, self->guest, arg0, arg1, arg2, arg3); }

#ifndef USDT_ONLY
pid$target::*invalidate_after_edit*:entry
{ printf("EDIT pid=%d tid=%d nr=%d\n", pid, tid, self->nr); }

pid$target::*ResumeInvalidation*owe*:entry
{ owed_events++; printf("OWE pid=%d tid=%d nr=%d\n", pid, tid, self->nr); }
#endif

carrick*:::hvpatch-tlb-invalidation
/pid == $target/
{ printf("HOST pid=%d tid=%d nr=%d asid=%d\n", pid, tid, self->nr, arg0); }

tick-1s { secs++; }
tick-1s /secs >= 120/ { exit(0); }

END { printf("ACCOUNTING services=%d owed_events=%d\n", services, owed_events); }
END /services == 0/ { printf("ERROR: syscall service probes did not fire\n"); exit(1); }
#ifndef USDT_ONLY
END /owed_events == 0/ { printf("ERROR: debt entry probes did not fire\n"); exit(1); }
#endif
