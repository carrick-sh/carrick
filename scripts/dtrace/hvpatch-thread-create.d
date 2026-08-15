#!/usr/sbin/dtrace -qs
/*
 * Attribute a Linux pthread_create failure on HVPatch to its guest syscall
 * boundary.  musl can return EAGAIN after stack mmap/mprotect setup or after
 * clone itself; printing only pthread_create's errno cannot distinguish them.
 * This stream records the selected setup syscalls and the bounded-vCPU
 * admissions while counting (but not printing) sched_yield churn.
 *
 * Provider ABI qualified on macOS 15.6.1 / arm64 on 2026-08-15:
 * - carrick*:::syscall-entry carries uint64 syscall number, char *name, and a
 *   pointer to six contiguous u64 arguments in arg2.
 * - carrick*:::syscall-return carries uint64 number, char *name, int64 retval,
 *   and int32 errno in args 0..3.
 * - carrick*:::mn-admit carries int32 Linux tid, uint32 slot, uint32 budget.
 * - carrick*:::mn-reclaim carries int32 Linux tid, uint32 old slot,
 *   uint32 new slot, int32 kind.
 * - carrick*:::mn-clone-outcome carries int32 Linux tid, uint32 stable phase
 *   ordinal, int32 Linux errno.  Phases are 0=admission closed,
 *   1=admission cancelled, 2=reserved, 3=host thread started,
 *   4=child cancelled before a slot, 5=admitted, 6=child cancelled before
 *   materialization, 7=materialized, 8=child cancelled after materialization,
 *   9=materialization failed, 10=host thread spawn failed, 11=start cancelled,
 *   12=child published before parent resume, 13=parent resumed/clone started,
 *   14=retval completed to the guest.
 * - carrick*:::mn-clone-tid-output carries int32 reserved Linux tid, uint32
 *   output role (0=parent, 1=child), uint64 guest address, and uint32 result
 *   (0=success, 1=out of bounds, 2=unsupported, 3=other host-map failure,
 *   4=sparse-backing failure, 5=frame-COW failure).
 * - carrick*:::hvpatch-frame-cow-trigger-identity/data and
 *   hvpatch-frame-cow-identity/data retain their structural-receipt ABI from
 *   hvpatch-frame-cow.d; they distinguish a syscall-write COW transaction
 *   from a direct TID-output write without making COW events mandatory.
 *
 * AArch64 syscall numbers selected here are sched_yield=124, munmap=215,
 * clone=220, execve=221, mmap=222, and mprotect=226.  PERTURBATION: LOW-MEDIUM:
 * mmap/munmap/mprotect/clone/exec events and admissions are printed, while the
 * hot sched_yield and reclaim paths are counted only.  Timing is diagnostic,
 * never performance evidence.  Zero selected syscall returns, DTrace errors,
 * or bounded termination make the capture fail closed.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    entries = 0;
    returns = 0;
    yields = 0;
    admits = 0;
    reclaims = 0;
    clone_outcomes = 0;
    clone_tid_outputs = 0;
    errors = 0;
    bounded = 0;
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
 (arg0 == 215 || arg0 == 220 || arg0 == 221 || arg0 == 222 || arg0 == 226)/
{
    this->a = (uint64_t *)copyin(arg2, 48);
    entries++;
    printf("HVPATCHTHREAD1|entry|timestamp=%llu|host_pid=%d|host_tid=%d|nr=%llu|name=%s|a0=0x%llx|a1=0x%llx|a2=0x%llx|a3=0x%llx|a4=0x%llx|a5=0x%llx\n",
        timestamp, pid, tid, (uint64_t)arg0, copyinstr(arg1),
        this->a[0], this->a[1], this->a[2], this->a[3], this->a[4], this->a[5]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
 (arg0 == 215 || arg0 == 220 || arg0 == 221 || arg0 == 222 || arg0 == 226)/
{
    returns++;
    printf("HVPATCHTHREAD1|return|timestamp=%llu|host_pid=%d|host_tid=%d|nr=%llu|name=%s|retval=%lld|errno=%d\n",
        timestamp, pid, tid, (uint64_t)arg0, copyinstr(arg1),
        (int64_t)arg2, (int)arg3);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 124/
{
    yields++;
}

carrick*:::mn-admit
/(pid == $target || progenyof($target))/
{
    admits++;
    printf("HVPATCHTHREAD1|admit|timestamp=%llu|host_pid=%d|host_tid=%d|linux_tid=%d|slot=%u|budget=%u\n",
        timestamp, pid, tid, (int)arg0, (uint32_t)arg1, (uint32_t)arg2);
}

carrick*:::mn-reclaim
/(pid == $target || progenyof($target))/
{
    reclaims++;
}

carrick*:::mn-clone-outcome
/(pid == $target || progenyof($target))/
{
    clone_outcomes++;
    printf("HVPATCHTHREAD1|clone-outcome|timestamp=%llu|host_pid=%d|host_tid=%d|linux_tid=%d|phase=%u|errno=%d\n",
        timestamp, pid, tid, (int)arg0, (uint32_t)arg1, (int)arg2);
}

carrick*:::mn-clone-tid-output
/(pid == $target || progenyof($target))/
{
    clone_tid_outputs++;
    printf("HVPATCHTHREAD1|clone-tid-output|timestamp=%llu|host_pid=%d|host_tid=%d|linux_tid=%d|role=%u|address=0x%llx|result=%u\n",
        timestamp, pid, tid, (int)arg0, (uint32_t)arg1, (uint64_t)arg2,
        (uint32_t)arg3);
}

carrick*:::hvpatch-frame-cow-trigger-identity
/(pid == $target || progenyof($target))/
{
    self->cow_pid = arg0;
    self->cow_tid = arg1;
    self->cow_mm = arg2;
    self->cow_asid = arg3;
    self->cow_class = arg4;
}

carrick*:::hvpatch-frame-cow-trigger
/(pid == $target || progenyof($target))/
{
    printf("HVPATCHTHREAD1|cow-trigger|timestamp=%llu|host_pid=%d|host_tid=%d|linux_pid=%d|linux_tid=%d|mm=%llu|asid=%u|class=%u|va=0x%llx\n",
        timestamp, pid, tid, self->cow_pid, self->cow_tid,
        (uint64_t)self->cow_mm,
        (uint32_t)self->cow_asid, (uint32_t)self->cow_class, (uint64_t)arg0);
}

carrick*:::hvpatch-frame-cow-identity
/(pid == $target || progenyof($target))/
{
    self->cow_pid = arg0;
    self->cow_tid = arg1;
    self->cow_mm = arg2;
    self->cow_asid = arg3;
    self->cow_phase = arg4;
}

carrick*:::hvpatch-frame-cow
/(pid == $target || progenyof($target))/
{
    printf("HVPATCHTHREAD1|cow|timestamp=%llu|host_pid=%d|host_tid=%d|linux_pid=%d|linux_tid=%d|mm=%llu|asid=%u|phase=%u|va=0x%llx|old_frame=%llu|new_frame=%llu|old_ipa=0x%llx|new_ipa=0x%llx\n",
        timestamp, pid, tid, self->cow_pid, self->cow_tid,
        (uint64_t)self->cow_mm,
        (uint32_t)self->cow_asid, (uint32_t)self->cow_phase, (uint64_t)arg0,
        (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3, (uint64_t)arg4);
}

dtrace:::ERROR
{
    errors++;
}

proc:::exit
/pid == $target/
{
    exit(0);
}

profile:::tick-1sec
/timestamp - started > 90 * 1000000000/
{
    bounded = 1;
    exit(0);
}

dtrace:::END
{
    printf("HVPATCHTHREAD1|summary|entries=%d|returns=%d|yields=%d|admits=%d|reclaims=%d|clone_outcomes=%d|clone_tid_outputs=%d|bounded=%d|errors=%d\n",
        entries, returns, yields, admits, reclaims, clone_outcomes,
        clone_tid_outputs, bounded, errors);
    exit(returns == 0 || clone_outcomes == 0 || clone_tid_outputs == 0 ||
        bounded != 0 || errors != 0 ? 1 : 0);
}
