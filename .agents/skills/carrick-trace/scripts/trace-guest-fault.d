#pragma D option quiet
/* Guest EL0 fault diagnostics. vcpu-fault gives esr/elr/far; vcpu-fault-regs
 * adds the decoded faulting instruction + the base register it dereferenced
 * (scalars, so they survive a fault that kills the process). For a data abort,
 * far == xRn + imm. Fires only on a fault — zero happy-path cost. */
carrick*:::vcpu-fault
/pid == $target || progenyof($target)/
{ printf("FAULT[%d] esr=%x elr=%x far=%x\n", pid, arg0, arg1, arg2); }

carrick*:::vcpu-fault-regs
/pid == $target || progenyof($target)/
{ printf("       insn=%08x Rn=x%d xRn=%x\n", arg3, (int)arg4, arg5); }

tick-1s { secs++; }
tick-1s /secs >= 15/ { exit(0); }
