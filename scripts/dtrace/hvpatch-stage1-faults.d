/*
 * Minimal HVPatch stage-1 fault attribution.
 *
 * WHAT: records the hardware ESR/FAR/instruction, the live serialized stage-1
 * walk, TTBR0, typed COW-trigger identity, and the sparse stage-2 lifecycle for
 * every guest memory fault. It
 * answers whether a fast-only failure is a stale/invalid descriptor, a
 * permission COW, or a missing stage-2 backing without enabling the much
 * heavier full frame-COW receipt. Trigger identity also joins a failing host
 * pthread to the Linux pid/tid/mm that owned the preceding handled fault.
 *
 * ABI (qualified live on macOS/arm64, 2026-08-14): `vcpu-fault-regs` args are
 * ESR, ELR, FAR, instruction, Rn, X[Rn]; `pt-fault-walk` args are VA and L0-L3
 * descriptors; `pt-fault-ttbr` args are VA and TTBR0. The three probes fire in
 * walk/TTBR/fault order for a terminal unhandled fault and walk/TTBR followed by
 * a COW trigger for a handled permission fault.
 *
 * PERTURBATION: low but nonzero. Only fault-path, typed trigger, and stage-2
 * lifecycle plus signal publication/delivery USDTs fire; no syscall, COW-copy,
 * or inventory hot path is instrumented. Once a trigger identifies Linux tid
 * 4, the script also records that forker's syscall-boundary register tuple;
 * this is intentionally a reducer-specific diagnostic and increases
 * perturbation on that one thread.
 */

#pragma D option quiet
#pragma D option strsize=256

dtrace:::BEGIN
{
    printf("HVPATCHFAULT1|header|version=1\n");
}

carrick*:::pt-fault-walk
/(pid == $target || progenyof($target))/
{
    printf("HVPATCHFAULT1|pte|ts=%d|host_pid=%d|host_tid=%d|va=%x|l0=%x|l1=%x|l2=%x|l3=%x\n",
        timestamp, pid, tid, arg0, arg1, arg2, arg3, arg4);
}

carrick*:::pt-fault-ttbr
/(pid == $target || progenyof($target))/
{
    printf("HVPATCHFAULT1|ttbr|ts=%d|host_pid=%d|host_tid=%d|va=%x|ttbr0=%x\n",
        timestamp, pid, tid, arg0, arg1);
}

carrick*:::hvpatch-frame-cow-trigger-identity
/(pid == $target || progenyof($target))/
{
    self->linux_pid = arg0;
    self->linux_tid = arg1;
    self->mm = arg2;
    self->asid = arg3;
    self->class = arg4;
    self->have_trigger_identity = 1;
}

carrick*:::vcpu-trap
/(pid == $target || progenyof($target)) && self->linux_tid == 4/
{
    this->regs = (uint64_t *)copyin(arg0, 72);
    printf("HVPATCHFAULT1|vcpu|ts=%d|host_pid=%d|host_tid=%d|linux_tid=4|pc=%x|sp=%x|fp=%x|lr=%x|nr=%d|x0=%x\n",
        timestamp, pid, tid, this->regs[0], this->regs[1], this->regs[2],
        this->regs[3], this->regs[4], this->regs[5]);
}

carrick*:::hvpatch-frame-cow-trigger
/(pid == $target || progenyof($target))/
{
    printf("HVPATCHFAULT1|trigger|ts=%d|host_pid=%d|host_tid=%d|linux_pid=%d|linux_tid=%d|mm=%d|asid=%d|class=%d|va=%x|syndrome=%x|far=%x|ttbr0=%x|identity=%d\n",
        timestamp, pid, tid, self->linux_pid, self->linux_tid,
        self->mm, self->asid, self->class, arg0, arg1, arg2, arg3,
        self->have_trigger_identity);
    self->have_trigger_identity = 0;
}

carrick*:::hvpatch-global-frame-stage2
/(pid == $target || progenyof($target))/
{
    this->phase = (uint32_t)arg0;
    this->phase == 0 ? global_frame_host[arg1] = arg3 : 0;
    printf("HVPATCHFAULT1|stage2|ts=%d|host_pid=%d|host_tid=%d|phase=%d|ipa=%x|length=%x|host=%x|perms=%x\n",
        timestamp, pid, tid, (uint32_t)arg0, arg1, arg2, arg3, arg4);
}

carrick*:::hvpatch-fork-frame
/(pid == $target || progenyof($target)) && arg3 >= 0x9b00000000 && arg4 == 0x4000 && global_frame_host[arg3] != 0/
{
    this->p0 = (uint32_t *)copyin(global_frame_host[arg3] + 0x5c, 4);
    this->p1 = (uint32_t *)copyin(global_frame_host[arg3] + 0x105c, 4);
    this->p2 = (uint32_t *)copyin(global_frame_host[arg3] + 0x205c, 4);
    this->p3 = (uint32_t *)copyin(global_frame_host[arg3] + 0x305c, 4);
    printf("HVPATCHFAULT1|fork_frame_headers|ts=%d|host_pid=%d|host_tid=%d|frame=%d|ipa=%x|p0=%x|p1=%x|p2=%x|p3=%x\n",
        timestamp, pid, tid, arg2, arg3, this->p0[0], this->p1[0], this->p2[0], this->p3[0]);
}

carrick*:::hvpatch-global-frame-owner-miss
/(pid == $target || progenyof($target))/
{
    printf("HVPATCHFAULT1|owner_miss|ts=%d|host_pid=%d|host_tid=%d|ipa=%x|length=%x|host=%x|owner_host=%x\n",
        timestamp, pid, tid, arg0, arg1, arg2, arg3);
}

carrick*:::vcpu-fault-regs
/(pid == $target || progenyof($target))/
{
    self->fault_elr = arg1;
    printf("HVPATCHFAULT1|fault|ts=%d|host_pid=%d|host_tid=%d|esr=%x|elr=%x|far=%x|insn=%x|rn=%d|xrn=%x\n",
        timestamp, pid, tid, arg0, arg1, arg2, arg3, (uint32_t)arg4, arg5);
}

carrick*:::vcpu-fault-gprs
/(pid == $target || progenyof($target))/
{
    printf("HVPATCHFAULT1|fault_gprs|ts=%d|host_pid=%d|host_tid=%d|elr=%x|x0=%x|x1=%x|x2=%x|x3=%x|x4=%x|x5=%x\n",
        timestamp, pid, tid, self->fault_elr, arg0, arg1, arg2, arg3, arg4, arg5);
    self->fault_elr = 0;
}

carrick*:::signal-publish
/(pid == $target || progenyof($target))/
{
    printf("HVPATCHFAULT1|signal_publish|ts=%d|host_pid=%d|host_tid=%d|target_tid=%d|signum=%d|kind=%d\n",
        timestamp, pid, tid, (int32_t)arg0, (int32_t)arg1, (int32_t)arg2);
}

carrick*:::signal-deliver
/(pid == $target || progenyof($target))/
{
    printf("HVPATCHFAULT1|signal_deliver|ts=%d|host_pid=%d|host_tid=%d|linux_tid=%d|signum=%d\n",
        timestamp, pid, tid, (int32_t)arg0, (int32_t)arg1);
}

carrick*:::signal-inject
/(pid == $target || progenyof($target))/
{
    printf("HVPATCHFAULT1|signal_inject|ts=%d|host_pid=%d|host_tid=%d|signum=%d|saved_pc=%x|new_sp=%x|handler=%x\n",
        timestamp, pid, tid, (int32_t)arg0, arg1, arg2, arg3);
}

carrick*:::signal-restore
/(pid == $target || progenyof($target))/
{
    printf("HVPATCHFAULT1|signal_restore|ts=%d|host_pid=%d|host_tid=%d|saved_pc=%x|sp=%x|magic=%x\n",
        timestamp, pid, tid, arg0, arg1, arg2);
}

proc:::exit
/pid == $target/
{
    exit(0);
}
