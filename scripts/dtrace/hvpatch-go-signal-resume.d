/*
 * HVPatch Go signal-frame resume attribution.
 *
 * WHAT: records Go's exact tgkill(2) request, Linux signal delivery, AArch64
 * sigframe inject/restore, guest exit/exit_group requests, typed Carrick
 * thread-loop terminal reasons, and terminal
 * guest-fault register tuples needed to
 * decide whether SIGURG async preemption is lost before kernel publication,
 * between publication and delivery, during rt_sigreturn, or after the restored
 * guest context resumes.  The host pid/tid, source/target Linux pid/tid,
 * timestamp, frame SP, saved PC, handler, fault instruction, and x0..x5 form the
 * join.  This deliberately omits unrelated syscalls, stage-2, and COW probes.
 *
 * ABI (qualified live on macOS/arm64, 2026-08-15):
 * - signal-deliver: Linux tid, Linux signum.
 * - signal-inject: Linux signum, saved PC, new frame SP, handler PC.
 * - signal-restore: restored PC, returning frame SP, Carrick frame magic.
 * - hvpatch-syscall-service-begin: source Linux pid/tid, ASID, syscall number.
 * - hvpatch-syscall-args: syscall number followed by guest args 0..3.  AArch64
 *   exit is nr 93, exit_group is nr 94, and tgkill is nr 131. The args probe
 *   fires immediately after service-begin on the same host thread.
 * - syscall-return: syscall number/name, signed retval, Linux errno.  The source
 *   identity and target tuple are retained on that dedicated host vCPU thread.
 * - hvpatch-thread-terminal: Linux pid/tid, Carrick registry tid, typed reason
 *   (0 guest exit, 1 loop-top exec replacement, 2 post-wait exec replacement,
 *   3 vfork parent terminal cancellation, 4 process-terminal loser), and
 *   reason-specific detail.
 * - vcpu-fault-regs: ESR, ELR, FAR, instruction, Rn, X[Rn].
 * - vcpu-fault-gprs: x0..x5 for the immediately preceding vcpu-fault-regs.
 *
 * PERTURBATION: potentially HIGH on process/thread-heavy Go workloads.  The
 * exact gcimporter reducer emitted more than 1,000 terminal receipts and timed
 * out under this script while completing in roughly 12-15 seconds untraced.
 * Use it only for identity/causality joins; every liveness result must be
 * re-proven without DTrace.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    printf("HVPATCHGOSIG1|header|version=2\n");
}

carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target)) &&
 ((uint64_t)arg3 == 93 || (uint64_t)arg3 == 94 || (uint64_t)arg3 == 131)/
{
    self->source_pid = (int32_t)arg0;
    self->source_tid = (int32_t)arg1;
    self->source_asid = (uint32_t)arg2;
    self->source_nr = (uint64_t)arg3;
}

carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target)) &&
 (self->source_nr == 93 || self->source_nr == 94) &&
 (uint64_t)arg0 == self->source_nr/
{
    printf("HVPATCHGOSIG1|guest_exit|ts=%llu|host_pid=%d|host_tid=%d|source_pid=%d|source_tid=%d|asid=%u|nr=%d|code=%d\n",
        timestamp, pid, tid, self->source_pid, self->source_tid,
        self->source_asid, self->source_nr, (int32_t)arg1);
}

carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target)) &&
 self->source_nr == 131 && (uint64_t)arg0 == 131/
{
    self->target_pid = (int32_t)arg1;
    self->target_tid = (int32_t)arg2;
    self->target_signum = (int32_t)arg3;
    printf("HVPATCHGOSIG1|tgkill|ts=%llu|host_pid=%d|host_tid=%d|source_pid=%d|source_tid=%d|asid=%u|target_pid=%d|target_tid=%d|signum=%d\n",
        timestamp, pid, tid, self->source_pid, self->source_tid,
        self->source_asid, self->target_pid, self->target_tid,
        self->target_signum);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (uint64_t)arg0 == 131/
{
    printf("HVPATCHGOSIG1|tgkill_return|ts=%llu|host_pid=%d|host_tid=%d|source_pid=%d|source_tid=%d|target_pid=%d|target_tid=%d|signum=%d|retval=%d|errno=%d\n",
        timestamp, pid, tid, self->source_pid, self->source_tid,
        self->target_pid, self->target_tid, self->target_signum,
        (int64_t)arg2, (int32_t)arg3);
    self->source_pid = 0;
    self->source_tid = 0;
    self->source_asid = 0;
    self->source_nr = 0;
    self->target_pid = 0;
    self->target_tid = 0;
    self->target_signum = 0;
}

carrick*:::signal-deliver
/(pid == $target || progenyof($target))/
{
    printf("HVPATCHGOSIG1|deliver|ts=%llu|host_pid=%d|host_tid=%d|linux_tid=%d|signum=%d\n",
        timestamp, pid, tid, (int32_t)arg0, (int32_t)arg1);
}

carrick*:::hvpatch-thread-terminal
/(pid == $target || progenyof($target))/
{
    printf("HVPATCHGOSIG1|thread_terminal|ts=%llu|host_pid=%d|host_tid=%d|linux_pid=%d|linux_tid=%d|registry_tid=%d|reason=%d|detail=%d\n",
        timestamp, pid, tid, (int32_t)arg0, (int32_t)arg1,
        (int32_t)arg2, (uint32_t)arg3, (int32_t)arg4);
}

carrick*:::signal-inject
/(pid == $target || progenyof($target))/
{
    printf("HVPATCHGOSIG1|inject|ts=%llu|host_pid=%d|host_tid=%d|signum=%d|saved_pc=0x%llx|frame_sp=0x%llx|handler=0x%llx\n",
        timestamp, pid, tid, (int32_t)arg0, arg1, arg2, arg3);
}

carrick*:::signal-restore
/(pid == $target || progenyof($target))/
{
    printf("HVPATCHGOSIG1|restore|ts=%llu|host_pid=%d|host_tid=%d|saved_pc=0x%llx|frame_sp=0x%llx|magic=0x%llx\n",
        timestamp, pid, tid, arg0, arg1, arg2);
}

carrick*:::vcpu-fault-regs
/(pid == $target || progenyof($target))/
{
    self->fault_elr = arg1;
    printf("HVPATCHGOSIG1|fault|ts=%llu|host_pid=%d|host_tid=%d|esr=0x%llx|elr=0x%llx|far=0x%llx|insn=0x%llx|rn=%d|xrn=0x%llx\n",
        timestamp, pid, tid, arg0, arg1, arg2, arg3, (uint32_t)arg4, arg5);
}

carrick*:::vcpu-fault-gprs
/(pid == $target || progenyof($target))/
{
    printf("HVPATCHGOSIG1|fault_gprs|ts=%llu|host_pid=%d|host_tid=%d|elr=0x%llx|x0=0x%llx|x1=0x%llx|x2=0x%llx|x3=0x%llx|x4=0x%llx|x5=0x%llx\n",
        timestamp, pid, tid, self->fault_elr, arg0, arg1, arg2, arg3, arg4, arg5);
    self->fault_elr = 0;
}

proc:::exit
/pid == $target/
{
    exit(0);
}
