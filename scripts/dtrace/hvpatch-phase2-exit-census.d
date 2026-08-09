/*
 * hvpatch-phase2-exit-census.d — count host-dispatched guest syscall exits
 * and rank them by canonical AArch64 syscall number.
 *
 * Provider ABI qualified on Darwin/arm64 on 2026-08-08 against Carrick's
 * single `carrick*:::vcpu-trap` USDT site: arg0 is a host pointer to the
 * repr(C) GuestRegs record whose first six u64 fields are pc, sp, fp, lr, x8,
 * and x0. The probe fires after the EL1 mailbox has decoded an HVC-forwarded
 * syscall and before host dispatch. EL1-serviced identity syscalls do not
 * reach this probe. The predicate follows Carrick descendants because the
 * current backend still uses host fork/exec descendants.
 *
 * Scope: this counts syscall-caused returns to the host. It does not claim to
 * count scheduler kicks or fault exits, for which no equivalent one-site USDT
 * lifecycle probe exists. A Phase gate citing this result must name it
 * "host-dispatched syscall exits", not generic VM exits.
 *
 * Perturbation: one copyin and two aggregation updates per dispatched guest
 * syscall. Counts and rank are citable; traced wall/CPU time is not. The 90 s
 * bound prevents a failed workload from leaving an unbounded consumer.
 *
 * Run from the repository root:
 *   target/release/carrick trace \
 *     --script scripts/dtrace/hvpatch-phase2-exit-census.d \
 *     --trace-out /tmp/hvpatch-phase2-exit-census.out -- \
 *     run --raw --exec-backend hvpatch IMAGE /bin/sh -c WORKLOAD
 */

#pragma D option quiet
#pragma D option bufsize=32m

typedef struct {
	uint64_t pc;
	uint64_t sp;
	uint64_t fp;
	uint64_t lr;
	uint64_t x8;
	uint64_t x0;
} hvpatch_regs_t;

dtrace:::BEGIN
{
	printf("HVPATCH2|begin\n");
}

carrick*:::vcpu-trap
/pid == $target || progenyof($target)/
{
	this->regs = (hvpatch_regs_t *)copyin(arg0, sizeof(hvpatch_regs_t));
	@by_nr[this->regs->x8] = count();
	@by_pc_nr[this->regs->pc, this->regs->x8] = count();
	exits++;
}

tick-1s
{
	seconds++;
}

/* The trace-launch child owns the workload and exits after its descendants. */
proc:::exit
/pid == $target/
{
	exit(0);
}

tick-1s
/seconds >= 90/
{
	bounded = 1;
	exit(0);
}

dtrace:::END
/exits == 0/
{
	printf("HVPATCH2|error|reason=zero-events|bounded=%d\n", bounded);
}

dtrace:::END
/exits != 0/
{
	printf("HVPATCH2|end|syscall_exits=%d|bounded=%d\n", exits, bounded);
	printa("HVPATCH2|nr|nr=%d|count=%@d\n", @by_nr);
	printa("HVPATCH2|pc_nr|pc=%#x|nr=%d|count=%@d\n", @by_pc_nr);
}
