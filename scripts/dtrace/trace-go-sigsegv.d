/*
 * Catch carrick INJECTING a SIGSEGV (signum 11) into the go toolchain.
 *
 * The go-build crash reports SIGSEGV addr=0x0 at a PC that is `CMN $4095,R0`
 * (the return-value check right after `svc` in Syscall6) — an instruction that
 * cannot perform a memory access. So the fault is injected, not a real guest
 * data abort. This trace records every SIGSEGV publish/inject with its source
 * and the guest PC the sigframe will resume at, to prove carrick is the source
 * and find which signal path produces it.
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option bufsize=32m

dtrace:::BEGIN { printf("go-sigsegv trace started\n"); }

/* signal_publish(target, signum, kind) — a signal becoming pending. */
carrick*:::signal-publish
/(int)arg1 == 11/
{
	printf("PUBLISH pid=%d target=%d signum=%d kind=%d\n",
	    pid, (int)arg0, (int)arg1, (int)arg2);
	ustack(8);
}

/* signal_inject(signum, saved_pc, new_sp, handler) — guest set up to run a handler. */
carrick*:::signal-inject
/(int)arg0 == 11/
{
	printf("INJECT pid=%d signum=%d saved_pc=%#x new_sp=%#x handler=%#x\n",
	    pid, (int)arg0, arg1, arg2, arg3);
}

/* The fatal fault itself (if a real one fires). */
carrick*:::vcpu-fault
{
	printf("FAULT pid=%d esr=%#x elr=%#x far=%#x\n", pid, arg0, arg1, arg2);
}

tick-1s { secs++; }
tick-1s /secs >= 60/ { exit(0); }
