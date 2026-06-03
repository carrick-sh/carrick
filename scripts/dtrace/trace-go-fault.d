/*
 * Post-mortem capture for the `go tool compile` SIGSEGV under carrick --fs host.
 *
 * Fires only at a fatal guest EL0 fault, so it is cheap and robust even though
 * the fault kills the process. Prints, per faulting guest process:
 *   - the authoritative HW-latched faulting pointer (far) + ESR + ELR,
 *   - the faulting instruction word (insn) and the base register it used,
 *   - the live stage-1 page-table descriptors at `far` (l0..l3): an INVALID
 *     leaf (bit0==0) while the host backing is fine == a stale-TLB coherence
 *     fault; a valid leaf == the mapping is established and the data is wrong.
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option bufsize=32m

dtrace:::BEGIN
{
	printf("go-fault trace started\n");
}

carrick*:::vcpu-fault
{
	printf("FAULT pid=%d tid=%d esr=%#x elr=%#x far=%#x lr=%#x sp=%#x\n",
	    pid, (int)arg5, arg0, arg1, arg2, arg3, arg4);
}

carrick*:::vcpu-fault-regs
{
	printf("FAULTREGS pid=%d esr=%#x elr=%#x far=%#x insn=%#x base_reg=x%d base_val=%#x\n",
	    pid, arg0, arg1, arg2, (uint32_t)arg3, (int)arg4, arg5);
}

carrick*:::pt-fault-walk
{
	printf("PTFAULT pid=%d far=%#x l0=%#x l1=%#x l2=%#x l3=%#x leaf_valid=%d\n",
	    pid, arg0, arg1, arg2, arg3, arg4, (int)(arg4 & 1));
}

tick-1s { secs++; }
tick-1s /secs >= 60/ { exit(0); }
