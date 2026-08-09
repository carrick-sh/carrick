/*
 * hvpatch-island-origin.d — prove that an hvpatch syscall trap originated
 * from a generated in-guest island rather than the original ELF text.
 *
 * Provider ABI qualified on Darwin/arm64 on 2026-08-08 against Carrick's
 * `carrick*:::vcpu-trap`: arg0 is a host pointer to the repr(C) GuestRegs
 * record whose first six u64 fields are pc, sp, fp, lr, x8, and x0. The pc is
 * the syscall resume PC (ELR_EL1), so the Phase 1 `svc; ret` island reports
 * island_base+4. The predicate follows Carrick descendants as required by the
 * trace harness contract.
 *
 * Perturbation: one copyin + one printf per guest syscall. Suitable for small
 * bring-up fixtures only; timings from this trace are not performance evidence.
 */

#pragma D option quiet

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
	printf("HVPATCH1|begin\n");
}

carrick*:::vcpu-trap
/pid == $target || progenyof($target)/
{
	this->regs = (hvpatch_regs_t *)copyin(arg0, sizeof(hvpatch_regs_t));
	@traps[this->regs->pc, this->regs->x8] = count();
	trap_count++;
	printf("HVPATCH1|trap|pid=%d|pc=%#x|nr=%d|x0=%#x\n",
	    pid, this->regs->pc, this->regs->x8, this->regs->x0);
}

tick-1s
{
	seconds++;
}

tick-1s
/seconds >= 5/
{
	exit(0);
}

dtrace:::END
/trap_count == 0/
{
	printf("HVPATCH1|error|reason=zero-events\n");
}

dtrace:::END
/trap_count != 0/
{
	printf("HVPATCH1|end|traps=%d\n", trap_count);
	printa("HVPATCH1|summary|pc=%#x|nr=%d|count=%@d\n", @traps);
}
